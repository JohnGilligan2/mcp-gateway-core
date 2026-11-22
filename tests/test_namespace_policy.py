"""A tool the caller is not entitled to must be invisible AND uncallable.

Hiding is not authorization. fastmcp's own search transform documents the trap:
"Hidden tools remain callable -- get_tool() delegates unknown names downstream".
So the gate is a per-tool AuthCheck, which fastmcp enforces on both the list
path and the resolution path inside call_tool, and the middleware exists to
turn "Unknown tool" into a sentence naming the group to ask for.

Both layers are tested independently, because a test that only exercises them
together would pass if either one silently stopped working.
"""

from __future__ import annotations

import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from mcp_gateway.naming import NamespaceOnce
from mcp_gateway.policy import (
    NO_ACCESS_TOOL,
    NamespaceGate,
    NamespacePolicy,
    NamespacePolicyMiddleware,
    held_roles,
    no_access_message,
)
from mcp_gateway.upstreams import ResilientProxyProvider, make_client_factory
from tests.conftest import make_upstream, serve
from tests.util import StubExchanger, cfg_for

POLICY = NamespacePolicy(
    roles={"inventory": "inventory.read", "docs": "docs.read"},
    groups={"inventory": "Inventory-MCP-Users", "docs": "Docs-MCP-Users"},
)

DOCS_ONLY = "token-docs-only"
NOTHING = "token-no-roles"
BOTH = "token-both"

TOKENS = {
    DOCS_ONLY: {"client_id": "gw", "sub": "dana", "scopes": [], "roles": ["docs.read"]},
    NOTHING: {"client_id": "gw", "sub": "newstarter", "scopes": [], "roles": []},
    BOTH: {
        "client_id": "gw",
        "sub": "admin",
        "scopes": [],
        "roles": ["inventory.read", "docs.read"],
    },
}


def build_gateway(configs, *, with_middleware: bool = True) -> FastMCP:
    middleware = [NamespacePolicyMiddleware(POLICY)] if with_middleware else []
    mcp: FastMCP = FastMCP(name="gw-test", auth=StaticTokenVerifier(TOKENS), middleware=middleware)

    # A REAL tool, as the server registers it, so it is callable as well as
    # listable. The middleware hides it from anyone entitled to something.
    @mcp.tool(name=NO_ACCESS_TOOL, description="Why you see nothing.")
    async def gw_no_access() -> str:
        return no_access_message(POLICY)

    for cfg in configs:
        provider = ResilientProxyProvider(cfg, make_client_factory(cfg, StubExchanger()))
        provider.add_transform(NamespaceGate(cfg.namespace, POLICY.roles[cfg.namespace]))
        mcp.add_provider(provider.wrap_transform(NamespaceOnce(cfg.namespace)))
    return mcp


def two_upstreams():
    return (
        serve(make_upstream("inventory", {"list_hosts": "hosts"})),
        serve(make_upstream("docs", {"docs_capabilities": "caps"})),
    )


def test_roles_are_read_from_the_roles_claim():
    token = type("T", (), {"claims": {"roles": ["inventory.read"]}})()
    assert held_roles(token) == {"inventory.read"}
    assert held_roles(None) == frozenset()


def test_a_groups_overage_pointer_denies_everything_rather_than_failing_open():
    """Entra truncates the groups claim past roughly 150 memberships and
    substitutes a pointer. A gate that sees no groups and shrugs is a gate that
    grants everything, so this must deny."""
    token = type("T", (), {"claims": {"_claim_names": {"groups": "src1"}}})()
    assert held_roles(token) == frozenset()
    assert POLICY.entitled(token) == frozenset()


async def test_unentitled_namespaces_are_hidden_and_uncallable():
    a, b = two_upstreams()
    with a as s1, b as s2:
        configs = [cfg_for("inventory", s1.url), cfg_for("docs", s2.url)]
        with serve(build_gateway(configs)) as gw:
            transport = StreamableHttpTransport(gw.url, auth=BearerAuth(DOCS_ONLY))
            async with Client(transport) as client:
                names = [t.name for t in await client.list_tools()]
                assert "docs_capabilities" in names
                assert not any(n.startswith("inventory_") for n in names)

                # By NAME, not merely absent from the list.
                with pytest.raises(Exception) as exc:
                    await client.call_tool("inventory_list_hosts", {})
                message = str(exc.value)
                # The refusal must name the group to ask for, not read as a bug.
                assert "Inventory-MCP-Users" in message, message
                assert "Nothing about this call reached" in message, message


async def test_the_gate_still_blocks_with_the_middleware_removed():
    """Proves the two layers are independent. The AuthCheck is the authorization;
    the middleware makes the refusal legible."""
    a, b = two_upstreams()
    with a as s1, b as s2:
        configs = [cfg_for("inventory", s1.url), cfg_for("docs", s2.url)]
        with serve(build_gateway(configs, with_middleware=False)) as gw:
            transport = StreamableHttpTransport(gw.url, auth=BearerAuth(DOCS_ONLY))
            async with Client(transport) as client:
                names = [t.name for t in await client.list_tools()]
                assert not any(n.startswith("inventory_") for n in names)
                with pytest.raises(Exception):
                    await client.call_tool("inventory_list_hosts", {})


async def test_a_user_with_every_role_sees_everything():
    """The positive control. Without it, a gate that denied everything would
    pass every other test in this file."""
    a, b = two_upstreams()
    with a as s1, b as s2:
        configs = [cfg_for("inventory", s1.url), cfg_for("docs", s2.url)]
        with serve(build_gateway(configs)) as gw:
            transport = StreamableHttpTransport(gw.url, auth=BearerAuth(BOTH))
            async with Client(transport) as client:
                names = [t.name for t in await client.list_tools()]
                assert "inventory_list_hosts" in names
                assert "docs_capabilities" in names
                result = await client.call_tool("inventory_list_hosts", {})
                assert result.data == "inventory:list_hosts"


async def test_a_user_with_no_roles_gets_a_loud_tool_not_an_empty_list():
    """An empty list reads as a broken connector and produces a ticket. Say why
    instead."""
    with serve(make_upstream("inventory", {"list_hosts": "hosts"})) as s1:
        with serve(build_gateway([cfg_for("inventory", s1.url)])) as gw:
            transport = StreamableHttpTransport(gw.url, auth=BearerAuth(NOTHING))
            async with Client(transport) as client:
                names = [t.name for t in await client.list_tools()]
                assert names == ["gw_no_access"], names
                result = await client.call_tool("gw_no_access", {})
                assert "Inventory-MCP-Users" in str(result.data)
