"""The inbound token must never reach an upstream.

This is the one test that guards a real security bug rather than a defect. Two
ways the gateway could leak the caller's gateway-audience token downstream, both
measured against fastmcp 3.4.5 and httpx 0.28.1:

  1. Passing the exchanged token as headers={"Authorization": ...}. httpx keeps
     a mixed-case duplicate rather than replacing, so BOTH headers go on the
     wire and the upstream receives the inbound token.
  2. Using ProxyClient or create_proxy(), which force
     forward_incoming_headers = True. That flag IS the passthrough.

The upstream fixture returns RAW headers, not get_http_headers(). A lowercased
dict view collapses the duplicate, which is exactly how this escapes review.
"""

from __future__ import annotations

import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from mcp_gateway import upstreams
from mcp_gateway.naming import NamespaceOnce
from mcp_gateway.upstreams import ResilientProxyProvider, make_client_factory
from tests.conftest import make_upstream, serve
from tests.util import StubExchanger, cfg_for

INBOUND = "INBOUND-SENTINEL-do-not-forward"
EXCHANGED = "OBO-SENTINEL-for-upstream"


def build_gateway(up, exchanger) -> FastMCP:
    mcp: FastMCP = FastMCP(
        name="gw-test",
        auth=StaticTokenVerifier(
            {INBOUND: {"client_id": "gateway-test", "sub": "tester", "scopes": []}}
        ),
    )
    provider = ResilientProxyProvider(up, make_client_factory(up, exchanger))
    mcp.add_provider(provider.wrap_transform(NamespaceOnce(up.namespace)))
    return mcp


def auth_headers(result) -> list[tuple[str, str]]:
    data = result.data if hasattr(result, "data") else result
    return [(k.lower(), v) for k, v in data["headers"] if k.lower() == "authorization"]


async def test_upstream_sees_exactly_one_authorization_header_and_not_the_inbound_one():
    upstream = make_upstream("inventory", {"list_hosts": "hosts"})
    with serve(upstream) as up_server:
        cfg = cfg_for("inventory", up_server.url)
        exchanger = StubExchanger(EXCHANGED)
        gateway = build_gateway(cfg, exchanger)

        with serve(gateway) as gw_server:
            transport = StreamableHttpTransport(url=gw_server.url, auth=BearerAuth(INBOUND))
            async with Client(transport) as client:
                # tools/list also opens an upstream connection, so both paths
                # are exercised before the assertions below.
                names = [t.name for t in await client.list_tools()]
                assert "inventory_echo_headers" in names

                result = await client.call_tool("inventory_echo_headers", {})

    data = result.data
    headers = auth_headers(result)
    assert len(headers) == 1, f"expected exactly one authorization header, got {headers}"
    assert headers[0][1] == f"Bearer {EXCHANGED}"

    flat = " ".join(f"{k}: {v}" for k, v in data["headers"])
    assert INBOUND not in flat, "the inbound token reached the upstream"

    assert exchanger.calls, "the gateway did not perform an exchange"
    for inbound_token, scope, upstream_name in exchanger.calls:
        assert inbound_token == INBOUND
        assert scope == cfg.scope
        assert upstream_name == cfg.name


async def test_client_factory_disables_header_forwarding():
    """ProxyClient and create_proxy() force this True; ours must be False.

    A unit-level guard against a refactor to the convenience proxy APIs, which
    would reintroduce passthrough without changing any behavior a functional
    test would notice until a real upstream started accepting the wrong token.
    """
    cfg = cfg_for("inventory", "http://127.0.0.1:1/mcp")
    factory = make_client_factory(cfg, StubExchanger(EXCHANGED))

    marker = upstreams.set_inbound_token(type("T", (), {"token": INBOUND, "claims": {}})())
    try:
        client = await factory()
    finally:
        upstreams.reset_inbound_token(marker)

    transport = client.transport
    assert transport.forward_incoming_headers is False
    assert isinstance(transport.auth, BearerAuth)
    # The Host header names the PUBLIC hostname even though we connect to a
    # host:port, because the token is audience-bound to the public /mcp URL.
    assert transport.headers.get("Host") == cfg.host_header
    # And no Authorization in the static headers dict: that is the duplicate trap.
    assert not any(k.lower() == "authorization" for k in transport.headers)


async def test_the_headers_trap_is_real():
    """Negative control: put the exchanged token in headers= with forwarding on,
    and the inbound token goes on the wire beside it. If this ever stops
    reproducing, the warning in upstreams.py should be revisited, not deleted."""
    from fastmcp.server.providers.proxy import ProxyProvider

    upstream = make_upstream("inventory", {"list_hosts": "hosts"})
    with serve(upstream) as up_server:

        async def leaky_factory() -> Client:
            transport = StreamableHttpTransport(
                url=up_server.url, headers={"Authorization": f"Bearer {EXCHANGED}"}
            )
            transport.forward_incoming_headers = True
            return Client(transport)

        mcp: FastMCP = FastMCP(
            name="leaky",
            auth=StaticTokenVerifier({INBOUND: {"client_id": "t", "sub": "t", "scopes": []}}),
        )
        mcp.add_provider(ProxyProvider(client_factory=leaky_factory))
        with serve(mcp) as gw_server:
            transport = StreamableHttpTransport(url=gw_server.url, auth=BearerAuth(INBOUND))
            async with Client(transport) as client:
                result = await client.call_tool("echo_headers", {})

    flat = " ".join(f"{k}: {v}" for k, v in result.data["headers"])
    assert INBOUND in flat, "negative control did not reproduce the passthrough"


async def test_gateway_refuses_rather_than_calling_upstream_anonymously():
    """With no identity in context, the factory must raise, not connect."""
    from fastmcp.exceptions import ToolError

    cfg = cfg_for("inventory", "http://127.0.0.1:1/mcp")
    factory = make_client_factory(cfg, StubExchanger(EXCHANGED))

    marker = upstreams.set_inbound_token(None)
    try:
        with pytest.raises(ToolError):
            await factory()
    finally:
        upstreams.reset_inbound_token(marker)
