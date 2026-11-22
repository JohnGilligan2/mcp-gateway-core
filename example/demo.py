"""The gateway end to end, offline.

Starts the made-up fleet from fleet.example.json as stub MCP servers on
127.0.0.1, puts the real gateway assembly (mcp_gateway.server.build_server) in
front of them, and walks through what it does. Identity is stubbed: a static
token verifier stands in for Entra on the way in, and a stub exchanger stands
in for the On-Behalf-Of call on the way out. Nothing leaves the machine.

    python example/demo.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastmcp import Client  # noqa: E402
from fastmcp.client.auth import BearerAuth  # noqa: E402
from fastmcp.client.transports import StreamableHttpTransport  # noqa: E402
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier  # noqa: E402

from mcp_gateway.config import AuthConfig, Config, ServerConfig, UpstreamConfig  # noqa: E402
from mcp_gateway.server import build_server  # noqa: E402
from scripts.measure_schema_tokens import measure_fleet_file, report  # noqa: E402
from scripts.stub_fleet import DEFAULT_FLEET, load_fleet, serve, serve_fleet  # noqa: E402

# Two people. Riley may use the inventory server only; Sam may use everything.
RILEY, SAM = "riley-inbound-token", "sam-inbound-token"
TOKENS = {
    RILEY: {"client_id": "demo", "sub": "riley", "preferred_username": "riley",
            "scopes": [], "roles": ["inventory.read"]},
    SAM: {"client_id": "demo", "sub": "sam", "preferred_username": "sam",
          "scopes": [], "roles": ["inventory.read", "docs.read", "helpdesk.read"]},
}


class StubExchanger:
    """Stands in for the Entra On-Behalf-Of exchange: one token per (user, upstream)."""

    def __init__(self) -> None:
        self.calls = 0

    async def token_for(self, inbound_token: str, scope: str, *, upstream: str) -> str:
        self.calls += 1
        who = TOKENS[inbound_token]["sub"]
        return f"exchanged-for-{who}-at-{upstream}"


def upstream(ns: str, name: str, group: str, url: str) -> UpstreamConfig:
    host = f"{ns}-mcp.example.com"
    return UpstreamConfig(
        name=name, namespace=ns, url=url, identifier_uri=f"https://{host}/mcp",
        host_header=host, scope=f"https://{host}/mcp/.default", group=group,
        init_timeout=3.0, call_timeout=10.0,
    )


def gateway_config(upstreams: list[UpstreamConfig], search: bool) -> Config:
    # The AuthConfig values only switch policy on; StaticTokenVerifier does the
    # actual validation in this demo, so nothing here is contacted.
    auth = AuthConfig(True, "example-tenant", "example-client", "https://gw.example.com/mcp",
                      "https://gw.example.com", "access_as_user", ("access_as_user",), True)
    server = ServerConfig("http", "127.0.0.1", 0, "/mcp", "", (), search, 8, "WARNING")
    return Config(server=server, auth=auth, obo=None, upstreams=tuple(upstreams))


def heading(n: int, text: str) -> None:
    print(f"\n{n}. {text}")
    print("-" * (len(text) + 3))


def names_in(result) -> list[str]:
    blob = json.dumps(result.data, default=str) if result.data is not None else ""
    for c in result.content or []:
        blob += getattr(c, "text", "") or ""
    try:
        items = json.loads(blob)
        return [t["name"] for t in items if isinstance(t, dict) and "name" in t]
    except (ValueError, TypeError):
        # Not a JSON list of tools: fall back to scanning for known names.
        return sorted({w.strip('",[]{}') for w in blob.split() if "_" in w})


async def run() -> None:
    # The gateway logs every denial and every dead upstream at WARNING, which is
    # right for a server and noise for a walkthrough.
    logging.basicConfig(level=logging.ERROR)
    if sys.platform == "win32":
        # Windows' proactor event loop logs a ConnectionResetError traceback when
        # a stub server thread closes a socket at teardown. Harmless, and it
        # would bury the walkthrough, so only that logger is quieted.
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    fleet = load_fleet(DEFAULT_FLEET)
    by_ns = {s["namespace"]: s for s in fleet}
    live = [s for s in fleet if s["namespace"] != "helpdesk"]

    with serve_fleet(live) as running:
        ups = [upstream(ns, by_ns[ns]["name"], by_ns[ns]["group"], srv.url)
               for ns, srv in running.items()]
        # The helpdesk server is configured but nothing is listening for it.
        ups.append(upstream("helpdesk", "helpdesk-mcp", "Helpdesk-MCP-Users",
                            "http://127.0.0.1:1/mcp"))

        exchanger = StubExchanger()

        # Flat first, so the namespacing is visible.
        flat = build_server(gateway_config(ups, search=False), obo=exchanger,
                            auth=StaticTokenVerifier(TOKENS))
        with serve(flat) as gw:
            async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(SAM))) as c:
                names = sorted(t.name for t in await c.list_tools())

                heading(1, "One endpoint, every tool namespaced once")
                print(f"Sam sees {len(names)} tools through one connector. A sample:")
                for n in ("inventory_list_hosts", "inventory_backup_status",
                          "docs_find_runbook", "docs_search"):
                    print(f"  {n}")
                print("inventory's bare names gained a prefix; docs already had one "
                      "and was not doubled (no docs_docs_*).")

                heading(2, "The caller's token never reaches an upstream")
                echo = (await c.call_tool("inventory_echo_headers", {})).data
                auth = [v for k, v in echo["headers"] if k.lower() == "authorization"]
                print(f"Authorization headers the inventory server received: {len(auth)}")
                print(f"  {auth[0]}")
                print("Sam's own gateway token appears in them: "
                      f"{any(SAM in v for v in auth)}")

                heading(3, "A dead server is visible, not silent")
                print(f"helpdesk_unavailable listed: {'helpdesk_unavailable' in names}")
                marker = (await c.call_tool("helpdesk_unavailable", {})).data
                print(f"  {marker}")

        # Now the production shape: policy plus tool search.
        prod = build_server(gateway_config(ups, search=True), obo=exchanger,
                            auth=StaticTokenVerifier(TOKENS))
        with serve(prod) as gw:
            heading(4, "Tool search, filtered per person")
            for who, token in (("Sam", SAM), ("Riley", RILEY)):
                async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(token))) as c:
                    listed = sorted(t.name for t in await c.list_tools())
                    res = await c.call_tool("search_tools",
                                            {"query": "runbook for a system documentation"})
                    found = [n for n in names_in(res) if n.startswith(("docs_", "inventory_"))]
                    print(f"{who}: tools/list is {listed}")
                    print(f"  search 'runbook for a system documentation' -> {found or 'nothing'}")

            async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(RILEY))) as c:
                print("Riley calls docs_find_runbook by name anyway:")
                try:
                    await c.call_tool("docs_find_runbook", {})
                    print("  (it ran, which would be a bug)")
                except Exception as exc:  # noqa: BLE001 - the refusal IS the output here
                    print(f"  refused: {exc}")

        print(f"\nExchange requests made: {exchanger.calls}. This stub mints a token per "
              "request; OBOExchanger caches one per user, per server, per token "
              "lifetime (tests/test_obo_cache.py).")

    heading(5, "What the catalog costs per turn, on this made-up fleet")
    report(await measure_fleet_file(DEFAULT_FLEET))


if __name__ == "__main__":
    asyncio.run(run())
