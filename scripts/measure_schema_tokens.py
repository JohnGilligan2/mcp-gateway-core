"""What a gateway costs in context, and what tool search saves.

Produces THREE numbers, not two, because the middle one is the one that
protects you:

  a) direct          every upstream connected separately
  b) gateway flat    one endpoint, namespaced, no tool search
  c) gateway search  one endpoint with the search transform on

(b) is expected to be WORSE than (a): namespacing lengthens every tool name and
the gateway adds its own tools, so naive aggregation makes the context problem
slightly worse rather than better. The value of a gateway is in filtering and
progressive disclosure, not in merging. Shipping (b) without (c) would be a
measurable regression, which is why this script refuses to report one without
the other.

The token estimate is byte-length / 4 over a JSON payload of
{name, description, inputSchema} per tool. That is the schema cost paid on
EVERY turn of a conversation, whether or not a tool is called.

Usage:

  # the made-up fleet in fleet.example.json, served as local stubs on 127.0.0.1
  python scripts/measure_schema_tokens.py

  # your own fleet file, same shape
  python scripts/measure_schema_tokens.py --fleet my-fleet.json

  # real servers, using a bearer token you already hold for all of them
  python scripts/measure_schema_tokens.py \
      --upstream inventory=https://inventory-mcp.example.com/mcp \
      --upstream docs=https://docs-mcp.example.com/mcp \
      --bearer "$TOKEN"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastmcp import Client, FastMCP  # noqa: E402
from fastmcp.client.auth import BearerAuth  # noqa: E402
from fastmcp.client.transports import StreamableHttpTransport  # noqa: E402

from mcp_gateway.config import UpstreamConfig  # noqa: E402
from mcp_gateway.naming import NamespaceOnce  # noqa: E402
from mcp_gateway.upstreams import ResilientProxyProvider, make_client_factory  # noqa: E402

CHARS_PER_TOKEN = 4


def _input_schema(tool) -> dict:
    """The input schema, whichever shape the tool object is.

    This normalization is load-bearing, not tidiness. A client's list_tools()
    returns mcp.types.Tool, which carries `inputSchema`. A server's own
    list_tools() returns fastmcp's Tool, which carries `parameters` and has NO
    `inputSchema` attribute at all. Reading only `inputSchema` silently scores
    every server-side tool as having an empty schema, which made flat
    aggregation look 25% CHEAPER than connecting directly -- a confidently wrong
    number that would have been reported as a saving. Caught by
    tests/test_measure.py.
    """
    for attr in ("inputSchema", "input_schema", "parameters"):
        value = getattr(tool, attr, None)
        if value:
            return value
    to_mcp = getattr(tool, "to_mcp_tool", None)
    if callable(to_mcp):
        try:
            return to_mcp().inputSchema or {}
        except Exception:  # noqa: BLE001
            # Swallowed: a tool we cannot convert is measured without its
            # schema, which UNDERSTATES the cost. The caller is told via the
            # count mismatch rather than being handed a silently low number.
            return {}
    return {}


def schema_tokens(tools) -> tuple[int, int, int]:
    """(tool_count, bytes, estimated tokens) for a tool list.

    Measures what the client is actually handed, because that is what occupies
    context on every subsequent turn whether a tool is called or not.
    """
    payload = [
        {
            "name": getattr(t, "name", ""),
            "description": getattr(t, "description", "") or "",
            "inputSchema": _input_schema(t),
        }
        for t in (tools or [])
    ]
    raw = json.dumps(payload, default=str).encode("utf-8")
    return len(payload), len(raw), int(len(raw) / CHARS_PER_TOKEN)


@dataclass
class Scenario:
    label: str
    tools: int
    bytes_: int
    tokens: int
    note: str = ""


def upstream_config(namespace: str, url: str) -> UpstreamConfig:
    """Config for measurement. Only `url` and `namespace` matter here."""
    host = f"{namespace}-mcp.example.com"
    return UpstreamConfig(
        name=f"{namespace}-mcp",
        namespace=namespace,
        url=url,
        identifier_uri=f"https://{host}/mcp",
        host_header=host,
        scope=f"https://{host}/mcp/.default",
        init_timeout=20.0,
    )


async def measure_direct(upstreams: list[UpstreamConfig], bearer: str | None) -> Scenario:
    """Every upstream connected separately."""
    total = [0, 0, 0]
    for up in upstreams:
        transport = StreamableHttpTransport(
            url=up.url, auth=BearerAuth(bearer) if bearer else None
        )
        async with Client(transport) as client:
            n, b, t = schema_tokens(await client.list_tools())
        total = [total[0] + n, total[1] + b, total[2] + t]
    return Scenario("direct", *total)


def build_gateway(
    upstreams: list[UpstreamConfig], bearer: str | None, search: bool
) -> FastMCP:
    """A gateway with no inbound auth, calling upstreams with a fixed bearer.

    Measurement only. The real gateway exchanges a per-user token; the schema
    size does not depend on which credential was used, so a fixed bearer keeps
    this script runnable without an identity provider.
    """

    class FixedToken:
        async def token_for(self, inbound_token, scope, *, upstream):
            return bearer

    mcp: FastMCP = FastMCP(name="mcp-gateway")
    mcp.provider_error_strategy = "raise"
    for up in upstreams:
        exchanger = FixedToken() if bearer else None
        if bearer:
            from mcp_gateway import upstreams as up_mod

            up_mod.set_inbound_token(type("T", (), {"token": bearer, "claims": {}})())
        provider = ResilientProxyProvider(up, make_client_factory(up, exchanger))
        mcp.add_provider(provider.wrap_transform(NamespaceOnce(up.namespace)))

    if search:
        from fastmcp.server.transforms.search.bm25 import BM25SearchTransform

        pinned = ["gw_status", *(f"{u.namespace}_unavailable" for u in upstreams)]
        mcp.add_transform(BM25SearchTransform(max_results=8, always_visible=pinned))

    @mcp.tool(name="gw_status", description="Gateway and upstream status.")
    async def gw_status() -> dict:
        return {}

    return mcp


async def measure_gateway(
    upstreams: list[UpstreamConfig], bearer: str | None, search: bool, label: str
) -> Scenario:
    mcp = build_gateway(upstreams, bearer, search)
    tools = await mcp.list_tools()
    n, b, t = schema_tokens(tools)
    note = ""
    if search:
        note = "visible: " + ", ".join(sorted(getattr(x, "name", "") for x in tools))
    return Scenario(label, n, b, t, note)


async def measure_all(upstreams: list[UpstreamConfig], bearer: str | None) -> list[Scenario]:
    return [
        await measure_direct(upstreams, bearer),
        await measure_gateway(upstreams, bearer, False, "gateway, flat"),
        await measure_gateway(upstreams, bearer, True, "gateway, tool search"),
    ]


def report(scenarios: list[Scenario], out=None) -> str:
    """The table, as text. Printed by main(); returned so tests can read it."""
    direct = scenarios[0]
    lines = [
        "",
        f"{'scenario':<22} {'tools':>7} {'bytes':>9} {'est tokens':>11}  {'vs direct':>10}",
        "-" * 66,
    ]
    for s in scenarios:
        if s is direct:
            delta = "baseline"
        else:
            pct = (s.tokens - direct.tokens) / direct.tokens * 100 if direct.tokens else 0
            delta = f"{pct:+.0f}%"
        lines.append(f"{s.label:<22} {s.tools:>7} {s.bytes_:>9} {s.tokens:>11}  {delta:>10}")
    lines.append("")
    for s in scenarios:
        if s.note:
            lines.append(f"  {s.label}: {s.note}")
    lines += [
        "",
        "Estimate is bytes/4 over {name, description, inputSchema} per tool.",
        "This is the SCHEMA cost paid on every turn of a conversation, whether or",
        "not a tool is called. It is not the cost of calling anything.",
    ]
    text = "\n".join(lines)
    print(text, file=out or sys.stdout)
    return text


async def measure_fleet_file(path: str | Path) -> list[Scenario]:
    """Serve every server in a fleet file as a loopback stub and measure."""
    from scripts.stub_fleet import load_fleet, serve_fleet

    servers = load_fleet(path)
    with serve_fleet(servers) as running:
        configs = [upstream_config(ns, srv.url) for ns, srv in running.items()]
        return await measure_all(configs, None)


def parse_upstream(spec: str) -> UpstreamConfig:
    namespace, _, url = spec.partition("=")
    if not namespace or not url:
        raise argparse.ArgumentTypeError(f"expected ns=url, got {spec!r}")
    return upstream_config(namespace, url)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--fleet", default=None, help="fleet file to serve as local stubs")
    parser.add_argument(
        "--upstream",
        action="append",
        default=[],
        metavar="NS=URL",
        help="repeatable; measure real servers instead of a fleet file",
    )
    parser.add_argument("--bearer", default=None, help="token for --upstream servers")
    args = parser.parse_args()

    if args.upstream:
        upstreams = [parse_upstream(s) for s in args.upstream]
        scenarios = asyncio.run(measure_all(upstreams, args.bearer))
    else:
        from scripts.stub_fleet import DEFAULT_FLEET

        scenarios = asyncio.run(measure_fleet_file(args.fleet or DEFAULT_FLEET))
    report(scenarios)


if __name__ == "__main__":
    main()
