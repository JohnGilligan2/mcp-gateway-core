"""The token exchange must be single-flight, bounded, and leak nothing.

The call-count assertions are the regression guard: if a
later "simplification" turns the in-flight-Task cache into a result cache, a
fan-out across three upstreams stops costing three exchanges and starts costing
one per tool. That is invisible in behavior and obvious in this count.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from mcp_gateway.obo import OBOError, OBOExchanger

USER_A = "eyJhbGciOiJSUzI1NiJ9.user-a-token.sig"
USER_B = "eyJhbGciOiJSUzI1NiJ9.user-b-token.sig"
SCOPE_1 = "https://inventory-mcp.example.com/mcp/.default"
SCOPE_2 = "https://docs-mcp.example.com/mcp/.default"


class Counter:
    def __init__(self, expires_in: int = 3600, delay: float = 0.0) -> None:
        self.count = 0
        self.expires_in = expires_in
        self.delay = delay

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.count += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        return httpx.Response(
            200,
            json={
                "access_token": f"exchanged-{self.count}",
                "expires_in": self.expires_in,
                "token_type": "Bearer",
            },
        )


def make(counter: Counter, **kwargs) -> OBOExchanger:
    client = httpx.AsyncClient(transport=httpx.MockTransport(counter.handler))
    return OBOExchanger(
        tenant_id="t", client_id="c", client_secret="s", http=client, **kwargs
    )


async def test_twenty_concurrent_callers_produce_one_exchange():
    """The stampede case. Without an in-flight-Task cache this is twenty."""
    counter = Counter()
    obo = make(counter)
    results = await asyncio.gather(
        *[obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp") for _ in range(20)]
    )
    assert counter.count == 1
    assert len(set(results)) == 1
    await obo.aclose()


async def test_distinct_users_and_scopes_do_not_share_a_token():
    """A shared token across users would be a cross-user identity leak, which is
    the whole thing On-Behalf-Of exists to prevent."""
    counter = Counter()
    obo = make(counter)
    a1 = await obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp")
    b1 = await obo.token_for(USER_B, SCOPE_1, upstream="inventory-mcp")
    a2 = await obo.token_for(USER_A, SCOPE_2, upstream="docs-mcp")
    assert counter.count == 3
    assert len({a1, b1, a2}) == 3
    # Same user, same scope again: served from cache.
    again = await obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp")
    assert again == a1
    assert counter.count == 3
    await obo.aclose()


async def test_a_cancelled_waiter_does_not_kill_the_shared_exchange():
    """asyncio.shield. Without it, one caller timing out cancels the exchange
    every other caller is awaiting, turning one client's hang-up into everyone's
    failure."""
    counter = Counter(delay=0.2)
    obo = make(counter)

    doomed = asyncio.create_task(obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp"))
    survivor = asyncio.create_task(
        obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp")
    )
    await asyncio.sleep(0.05)
    doomed.cancel()
    with pytest.raises(asyncio.CancelledError):
        await doomed

    assert await survivor == "exchanged-1"
    assert counter.count == 1
    await obo.aclose()


async def test_expiry_uses_the_reported_lifetime_minus_a_safety_margin():
    counter = Counter(expires_in=3600)
    obo = make(counter)
    await obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp")
    entry = next(iter(obo._entries.values()))
    import time

    remaining = entry.expires_at - time.monotonic()
    assert 3400 < remaining <= 3480, remaining
    await obo.aclose()


async def test_a_very_short_lifetime_is_floored_rather_than_thrashing():
    counter = Counter(expires_in=5)
    obo = make(counter)
    await obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp")
    entry = next(iter(obo._entries.values()))
    import time

    remaining = entry.expires_at - time.monotonic()
    assert 25 < remaining <= 30, remaining
    await obo.aclose()


async def test_the_cache_is_bounded():
    counter = Counter()
    obo = make(counter, max_entries=4)
    for i in range(12):
        await obo.token_for(f"{USER_A}-{i}", SCOPE_1, upstream="inventory-mcp")
    assert len(obo._entries) <= 4
    await obo.aclose()


async def test_a_failure_is_shared_by_every_waiter_and_classified():
    """One rejection, not twelve. A fan-out against an upstream the user is not
    assigned to must not hammer Entra with the same doomed request per tool."""
    calls = {"n": 0}

    async def refuse(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(
            400,
            json={
                "error": "invalid_grant",
                "error_description": (
                    "AADSTS65001: The user or administrator has not consented to "
                    "use the application."
                ),
                "correlation_id": "abc-123",
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(refuse))
    obo = OBOExchanger("t", "c", "s", http=client)

    results = await asyncio.gather(
        *[obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp") for _ in range(5)],
        return_exceptions=True,
    )
    assert calls["n"] == 1
    assert all(isinstance(r, OBOError) for r in results)
    err = results[0]
    assert isinstance(err, OBOError)
    assert err.kind == "not_consented"
    assert err.aadsts == "AADSTS65001"
    assert err.correlation_id == "abc-123"
    assert err.operator_fault is True
    await obo.aclose()


async def test_step_up_is_recognized_from_the_oauth_error_not_only_the_code():
    async def refuse(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "error": "interaction_required",
                "error_description": "AADSTS50076: MFA required.",
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(refuse))
    obo = OBOExchanger("t", "c", "s", http=client)
    with pytest.raises(OBOError) as exc:
        await obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp")
    assert exc.value.kind == "step_up"
    assert exc.value.operator_fault is False
    await obo.aclose()


async def test_a_200_with_no_token_is_refused_rather_than_passed_through():
    """Fail-unknown, never fail-clean. Returning None here would mean calling
    the upstream with no credential at all."""

    async def empty(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer", "expires_in": 3600})

    client = httpx.AsyncClient(transport=httpx.MockTransport(empty))
    obo = OBOExchanger("t", "c", "s", http=client)
    with pytest.raises(OBOError):
        await obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp")
    await obo.aclose()


async def test_nothing_in_the_cache_repr_reveals_a_token():
    """An MCP result and a container log both land somewhere durable, so a
    leaked bearer token is leaked permanently."""
    counter = Counter()
    obo = make(counter)
    await obo.token_for(USER_A, SCOPE_1, upstream="inventory-mcp")

    blob = f"{obo!r} {obo._entries!r}"
    assert USER_A not in blob
    assert "exchanged-1" not in blob
    # The task state is shown, the task's result is not.
    assert "ready" in blob
    await obo.aclose()
