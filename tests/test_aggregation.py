"""One endpoint lists several servers' tools under distinct namespaces, every
tool still executes, and one dead upstream degrades to a visible marker rather
than to silence or to a dead connector. Exercised over real HTTP.
"""

from __future__ import annotations

import pytest
from fastmcp import Client, FastMCP

from mcp_gateway.naming import NamespaceOnce
from mcp_gateway.server import CollisionGuardMiddleware
from mcp_gateway.upstreams import ResilientProxyProvider, make_client_factory
from tests.conftest import make_upstream, serve
from tests.util import cfg_for

# docs self-prefixes its tools; inventory and helpdesk do not. Both shapes must
# come out right through one gateway.
UPSTREAM_TOOLS = {
    "inventory": {"list_hosts": "Hosts", "list_sites": "Sites"},
    "docs": {"docs_capabilities": "What this does", "docs_search": "Search"},
    "helpdesk": {"get_summary": "Ticket summary"},
}


def build_gateway(configs) -> FastMCP:
    mcp: FastMCP = FastMCP(name="gw-test")
    mcp.provider_error_strategy = "raise"
    for cfg in configs:
        provider = ResilientProxyProvider(cfg, make_client_factory(cfg, None))
        mcp.add_provider(provider.wrap_transform(NamespaceOnce(cfg.namespace)))
    return mcp


async def test_three_upstreams_aggregate_under_distinct_namespaces():
    with (
        serve(make_upstream("inventory", UPSTREAM_TOOLS["inventory"])) as s1,
        serve(make_upstream("docs", UPSTREAM_TOOLS["docs"])) as s2,
        serve(make_upstream("helpdesk", UPSTREAM_TOOLS["helpdesk"])) as s3,
    ):
        configs = [
            cfg_for("inventory", s1.url),
            cfg_for("docs", s2.url),
            cfg_for("helpdesk", s3.url),
        ]
        with serve(build_gateway(configs)) as gw:
            async with Client(gw.url) as client:
                names = sorted(t.name for t in await client.list_tools())

                # Bare upstream names gain a prefix.
                assert "inventory_list_hosts" in names
                assert "helpdesk_get_summary" in names
                # Already-prefixed names are NOT doubled.
                assert "docs_capabilities" in names
                assert "docs_docs_capabilities" not in names
                # Every tool appears exactly once.
                assert len(names) == len(set(names))

                # And they execute, routed to the right server.
                assert (await client.call_tool("inventory_list_hosts", {})).data == (
                    "inventory:list_hosts"
                )
                assert (await client.call_tool("docs_capabilities", {})).data == (
                    "docs:docs_capabilities"
                )
                assert (await client.call_tool("helpdesk_get_summary", {})).data == (
                    "helpdesk:get_summary"
                )


async def test_one_dead_upstream_degrades_visibly_and_spares_the_others():
    """Fail-unknown, never fail-clean. A dead upstream must never be
    indistinguishable from a healthy one with no tools."""
    with (
        serve(make_upstream("inventory", UPSTREAM_TOOLS["inventory"])) as s1,
        serve(make_upstream("docs", UPSTREAM_TOOLS["docs"])) as s2,
    ):
        configs = [
            cfg_for("inventory", s1.url),
            cfg_for("docs", s2.url),
            # Nothing is listening on this port.
            cfg_for("helpdesk", "http://127.0.0.1:1/mcp"),
        ]
        with serve(build_gateway(configs)) as gw:
            async with Client(gw.url) as client:
                names = sorted(t.name for t in await client.list_tools())

                # The listing SUCCEEDS. One dead upstream must not make the
                # whole connector look dead.
                assert "inventory_list_hosts" in names
                assert "docs_capabilities" in names

                # And the dead one is visible, not silent.
                assert "helpdesk_unavailable" in names
                assert not any(
                    n.startswith("helpdesk_") and n != "helpdesk_unavailable" for n in names
                )

                # Calling the marker explains itself rather than erroring.
                marker = await client.call_tool("helpdesk_unavailable", {})
                assert "helpdesk-mcp" in str(marker.data)

                # Healthy namespaces are completely unaffected.
                assert (await client.call_tool("inventory_list_sites", {})).data == (
                    "inventory:list_sites"
                )


async def test_the_collision_guard_refuses_an_ambiguous_catalog():
    """Two providers wired WITHOUT namespacing publish the same bare name. The
    guard must fail the listing loudly rather than hand over a catalog where one
    name means two servers."""
    with (
        serve(make_upstream("phonea", {"list_devices": "Devices"})) as s1,
        serve(make_upstream("phoneb", {"list_devices": "Devices"})) as s2,
    ):
        mcp: FastMCP = FastMCP(name="gw-test", middleware=[CollisionGuardMiddleware()])
        mcp.provider_error_strategy = "raise"
        for ns, srv in (("phonea", s1), ("phoneb", s2)):
            cfg = cfg_for(ns, srv.url)
            mcp.add_provider(ResilientProxyProvider(cfg, make_client_factory(cfg, None)))
        with serve(mcp) as gw:
            async with Client(gw.url) as client:
                with pytest.raises(Exception) as exc:
                    await client.list_tools()
                assert "list_devices" in str(exc.value)
