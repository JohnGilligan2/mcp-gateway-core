"""A missing caller says nothing about the upstream, so it is never cached.

In production, after every redeploy, callers got "could not determine who is
calling" for 30 seconds. The boot-time listing runs with no caller token, the
provider cached that refusal as an upstream failure, and every real call inside
the failure TTL got the cached error. A real upstream failure is still cached.
"""

from __future__ import annotations

from fastmcp.exceptions import ToolError

from mcp_gateway.upstreams import (
    NO_IDENTITY_MESSAGE,
    ResilientProxyProvider,
    is_no_identity,
    make_client_factory,
)
from tests.conftest import make_upstream, serve
from tests.util import cfg_for


def _provider(url: str, first_call_has_no_caller: bool):
    cfg = cfg_for("inventory", url)
    real = make_client_factory(cfg, None)
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        if first_call_has_no_caller and calls["n"] == 1:
            raise ToolError(NO_IDENTITY_MESSAGE)  # what current_inbound_token raises
        return await real()

    return ResilientProxyProvider(cfg, factory)


async def test_boot_listing_without_a_caller_does_not_poison_the_next_request():
    with serve(make_upstream("inventory", {"list_hosts": "h"})) as up:
        p = _provider(up.url, first_call_has_no_caller=True)
        first = [t.name for t in await p._list_tools()]
        assert first == ["unavailable"], first  # visible for that request
        assert p.failure is None  # and NOT remembered
        second = [t.name for t in await p._list_tools()]  # the next caller, immediately
        assert "list_hosts" in second and "unavailable" not in second, second


async def test_a_real_upstream_failure_is_still_cached():
    p = _provider("http://127.0.0.1:1/mcp", first_call_has_no_caller=False)
    await p._list_tools()
    assert p.failure is not None and p.failure.is_fresh(p.failure.at)


def test_only_the_exact_refusal_counts_as_no_identity():
    assert is_no_identity(ToolError(NO_IDENTITY_MESSAGE))
    assert not is_no_identity(ToolError("Unknown tool"))
    assert not is_no_identity(RuntimeError(NO_IDENTITY_MESSAGE))
