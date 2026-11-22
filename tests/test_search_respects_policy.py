"""With tool search ON, a user must not be able to SEARCH for a tool they are
not entitled to.

This is the property the whole design rests on, and it is NOT the same property
test_namespace_policy.py checks. That file proves `tools/list` is filtered. But
with tool search on, `tools/list` returns only three tools and the real catalog
is reached through `search_tools`. If search were unfiltered, every user could
discover every tool in the fleet by searching for it, and the list filtering
would be decorative.

The intended experience: a teammate does not get "you cannot reach that tool",
they simply do not have it. Nothing to find, nothing to call.

Asserted separately, because they can fail independently:
  1. search_tools returns only the caller's namespaces.
  2. the search transform's own call_tool proxy cannot execute an unentitled
     tool; that proxy is a second execution path and needs its own guard.
  3. a direct call by name still fails, for the caller who somehow knows it.
  4. each of the two policy layers keeps search clean on its own, and with
     both removed the leak is real (the negative control that proves the
     test can fail).
"""

from __future__ import annotations

import json

import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from mcp_gateway import server as gw_server
from mcp_gateway.config import Config, ServerConfig
from mcp_gateway.naming import NamespaceOnce
from mcp_gateway.policy import NamespaceGate, NamespacePolicy, NamespacePolicyMiddleware
from mcp_gateway.upstreams import ResilientProxyProvider, make_client_factory
from tests.conftest import make_upstream, serve
from tests.util import StubExchanger, cfg_for

POLICY = NamespacePolicy(
    roles={"inventory": "inventory.read", "docs": "docs.read", "mail": "mail.read"},
    groups={
        "inventory": "Inventory-MCP-Users",
        "docs": "Docs-MCP-Users",
        "mail": "Mail-MCP-Users",
    },
)

# Riley is in Inventory-MCP-Users and nothing else. Sam is in everything.
RILEY = "token-riley"
SAM = "token-sam"
TOKENS = {
    RILEY: {
        "client_id": "gw",
        "sub": "riley",
        "preferred_username": "riley",
        "scopes": [],
        "roles": ["inventory.read"],
    },
    SAM: {
        "client_id": "gw",
        "sub": "sam",
        "preferred_username": "sam",
        "scopes": [],
        "roles": ["inventory.read", "docs.read", "mail.read"],
    },
}

# Descriptions matter here: BM25 ranks on them, so a search for "mailbox
# forwarding" must be able to find the mail tool if it is visible at all.
FLEET = {
    "inventory": {
        "cluster_health": "Cluster status rollup: quorum, per-node online state.",
        "list_nodes": "All cluster nodes with CPU, memory, disk and uptime.",
    },
    "docs": {
        "docs_find_organization": "Resolve a customer name to a documentation organization.",
        "docs_search_documents": "Search customer documentation for a keyword.",
    },
    "mail": {
        "mail_get_forwarding": "Mailbox forwarding rules for a user. Mail exfiltration check.",
        "mail_get_mailbox_rules": "Inbox rules including hidden ones. Mailbox persistence check.",
    },
}

LEAK_QUERIES = [
    "mailbox forwarding rules",
    "customer documentation search",
    "exfiltration",
    "organization",
    "",
    "tool",
]


def build_gateway(configs, *, gate: bool = True, middleware: bool = True) -> FastMCP:
    """The production shape: policy gate AND tool search both on."""
    mcp: FastMCP = FastMCP(
        name="gw-test",
        auth=StaticTokenVerifier(TOKENS),
        middleware=[NamespacePolicyMiddleware(POLICY)] if middleware else [],
    )
    proxies = []
    for cfg in configs:
        provider = ResilientProxyProvider(cfg, make_client_factory(cfg, StubExchanger()))
        if gate:
            provider.add_transform(NamespaceGate(cfg.namespace, POLICY.roles[cfg.namespace]))
        proxies.append(provider)
        mcp.add_provider(provider.wrap_transform(NamespaceOnce(cfg.namespace)))
    mcp.gateway_proxies = proxies
    gw_server.add_tool_search(mcp, [c.namespace for c in configs], max_results=20)
    return mcp


def three_upstreams():
    return [serve(make_upstream(ns, FLEET[ns])) for ns in ("inventory", "docs", "mail")]


def names_in(result) -> set[str]:
    """Tool names mentioned anywhere in a search result, whatever its shape."""
    blob = json.dumps(result.data, default=str) if result.data is not None else ""
    for c in result.content or []:
        blob += getattr(c, "text", "") or ""
    found = set()
    for ns, tools in FLEET.items():
        for raw in tools:
            for candidate in {raw, f"{ns}_{raw}"}:
                if candidate in blob:
                    found.add(candidate)
    return found


def foreign(names: set[str]) -> set[str]:
    return {n for n in names if n.startswith(("docs", "mail"))}


async def leaks_for_riley(*, gate: bool, middleware: bool) -> set[str]:
    a, b, c = three_upstreams()
    with a as s1, b as s2, c as s3:
        configs = [cfg_for("inventory", s1.url), cfg_for("docs", s2.url), cfg_for("mail", s3.url)]
        with serve(build_gateway(configs, gate=gate, middleware=middleware)) as gw:
            async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(RILEY))) as client:
                leaked: set[str] = set()
                for query in LEAK_QUERIES:
                    res = await client.call_tool("search_tools", {"query": query})
                    leaked |= foreign(names_in(res))
                return leaked


async def test_search_returns_only_the_callers_namespaces():
    """The load-bearing test. Riley searching for anything must never surface a
    docs or mail tool, even with queries aimed straight at them."""
    assert await leaks_for_riley(gate=True, middleware=True) == set()


async def test_search_stays_clean_with_only_the_gate():
    assert await leaks_for_riley(gate=True, middleware=False) == set()


async def test_search_stays_clean_with_only_the_middleware():
    assert await leaks_for_riley(gate=False, middleware=True) == set()


async def test_with_both_layers_removed_search_leaks():
    """Negative control. Without it the three tests above could pass against a
    search transform that never returned anything foreign for any reason."""
    leaked = await leaks_for_riley(gate=False, middleware=False)
    assert leaked, "expected docs/mail tools to leak with no policy at all"


async def test_search_still_finds_what_the_caller_does_have():
    """Positive control. A gate that returned nothing to anybody would pass the
    leak test and be useless."""
    a, b, c = three_upstreams()
    with a as s1, b as s2, c as s3:
        configs = [cfg_for("inventory", s1.url), cfg_for("docs", s2.url), cfg_for("mail", s3.url)]
        with serve(build_gateway(configs)) as gw:
            async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(RILEY))) as client:
                res = await client.call_tool("search_tools", {"query": "cluster nodes quorum"})
                assert any(n.startswith("inventory") or n in FLEET["inventory"] for n in names_in(res))


async def test_a_fully_entitled_user_can_search_everything():
    """The other positive control: the filter is per user, not global."""
    a, b, c = three_upstreams()
    with a as s1, b as s2, c as s3:
        configs = [cfg_for("inventory", s1.url), cfg_for("docs", s2.url), cfg_for("mail", s3.url)]
        with serve(build_gateway(configs)) as gw:
            async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(SAM))) as client:
                res = await client.call_tool("search_tools", {"query": "mailbox forwarding rules"})
                assert any(n.startswith("mail") for n in names_in(res))


async def test_the_search_call_tool_proxy_cannot_execute_an_unentitled_tool():
    """The search transform publishes its OWN call_tool proxy, which is a second
    execution path. If it bypassed the auth checks, a caller who guessed a name
    could run it even though search never showed it."""
    a, _, c = three_upstreams()
    with a as s1, c as s3:
        configs = [cfg_for("inventory", s1.url), cfg_for("mail", s3.url)]
        with serve(build_gateway(configs)) as gw:
            async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(RILEY))) as client:
                ok = await client.call_tool(
                    "call_tool", {"name": "inventory_cluster_health", "arguments": {}}
                )
                assert "inventory" in json.dumps(ok.data, default=str)

                with pytest.raises(Exception) as exc:
                    await client.call_tool(
                        "call_tool", {"name": "mail_get_forwarding", "arguments": {}}
                    )
                text = str(exc.value).lower()
                assert "mail" in text or "unknown" in text


async def test_a_direct_call_by_name_is_still_refused():
    a, _, c = three_upstreams()
    with a as s1, c as s3:
        configs = [cfg_for("inventory", s1.url), cfg_for("mail", s3.url)]
        with serve(build_gateway(configs)) as gw:
            async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(RILEY))) as client:
                with pytest.raises(Exception):
                    await client.call_tool("mail_get_forwarding", {})


async def test_gw_status_answers_what_tools_do_i_have_completely():
    """The "what tools do I have" path, which is the first thing anyone asks.

    It cannot rely on search: BM25 scores against query terms, so an empty
    query returns ZERO results, which would read as "you have nothing". So
    gw_status enumerates the caller's tool NAMES (never schemas).

    It must also not mention servers the caller cannot use. Not "docs: denied",
    absent entirely.
    """
    a, b, c = three_upstreams()
    with a as s1, b as s2, c as s3:
        configs = [cfg_for("inventory", s1.url), cfg_for("docs", s2.url), cfg_for("mail", s3.url)]
        mcp = build_gateway(configs)
        fake_cfg = Config(
            server=ServerConfig("http", "127.0.0.1", 0, "/mcp", "", (), True, 8, "INFO"),
            auth=None,
            obo=None,
            upstreams=tuple(configs),
        )
        object.__setattr__(fake_cfg, "auth", type("A", (), {})())  # make cfg.auth truthy
        gw_server._register_local_tools(mcp, fake_cfg, POLICY)

        with serve(mcp) as gw:
            async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(RILEY))) as client:
                data = (await client.call_tool("gw_status", {})).data
                blob = json.dumps(data, default=str)

                assert data["your_servers"] == ["inventory-mcp"], data["your_servers"]
                names = data["servers"][0]["tools"]
                for raw in FLEET["inventory"]:
                    assert f"inventory_{raw}" in names, f"{raw} missing from {names}"
                assert all(n.startswith("inventory_") for n in names), names
                assert data["total_tools_available_to_you"] == len(names)
                for forbidden in ("docs", "mail"):
                    assert forbidden not in blob, f"{forbidden!r} leaked into gw_status"

            async with Client(StreamableHttpTransport(gw.url, auth=BearerAuth(SAM))) as client:
                data = (await client.call_tool("gw_status", {})).data
                assert sorted(data["your_servers"]) == ["docs-mcp", "inventory-mcp", "mail-mcp"]
                every = {
                    raw if raw.startswith(ns) else f"{ns}_{raw}"
                    for ns, tools in FLEET.items()
                    for raw in tools
                }
                listed = {n for s in data["servers"] for n in s["tools"]}
                assert every <= listed, f"missing: {every - listed}"
