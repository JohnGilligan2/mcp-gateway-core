"""Connecting to the upstream MCP servers, and failing legibly when one is down.

Two jobs live here.

HEADER HYGIENE, which is the security-critical half. The inbound token is bound
to the GATEWAY's audience; forwarding it to an upstream is prohibited by the MCP
specification and would be rejected on audience anyway. Two traps, both measured
against the installed fastmcp 3.4.5 and httpx 0.28.1:

  * Passing the exchanged token as `headers={"Authorization": ...}` while header
    forwarding is on puts TWO authorization headers on the wire. Reproduced
    deliberately in this repo as a negative control; the upstream received
      [('authorization', 'Bearer INBOUND'), ('authorization', 'Bearer OBO')]
    and the FIRST one is the caller's gateway-audience token. Passing via
    `auth=` sets the header through httpx's auth flow instead, yielding exactly
    one. So: auth=, NEVER headers=.
  * ProxyClient and create_proxy() both force forward_incoming_headers = True,
    which IS the passthrough. That is why this module builds its own Client and
    sets the flag False explicitly. Anyone "simplifying" this back to
    create_proxy() reintroduces the bug silently.

tests/test_no_token_passthrough.py asserts both, at the wire level and at the
unit level, and both assertions were confirmed to FAIL with the bug reinstated.

DEGRADATION. fastmcp's AggregateProvider offers two strategies and neither meets
the fail-loud rule: "warn" silently drops a failed upstream's entire tool list, and
"raise" kills the whole tools/list so one dead upstream makes the connector look
dead. So each upstream catches its own expected failures and degrades to a
VISIBLE marker tool, while the aggregate strategy is set to "raise" so anything
still escaping is a genuine bug and is loud.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from contextvars import ContextVar
from dataclasses import dataclass

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.providers.proxy import ProxyProvider
from fastmcp.tools.base import Tool
from fastmcp.utilities.versions import VersionSpec

from .config import UpstreamConfig
from .obo import OBOError, OBOExchanger

logger = logging.getLogger("mcp_gateway.upstreams")

# How long a known-bad upstream stays known-bad. tools/list fans out to every
# provider concurrently, so without a backoff one dead upstream adds its full
# connect timeout to EVERY list, for every user.
_FAILURE_TTL_S = 30.0

MARKER_TOOL = "unavailable"

# Captured at the top of every request by TokenCaptureMiddleware. The proxy's
# client_factory is invoked inside the request (verified by execution on both
# the tools/list and tools/call paths under stateless_http=True), so
# get_access_token() works there too -- this is belt and braces against a future
# move off stateless mode or a background-task path.
_INBOUND: ContextVar[AccessToken | None] = ContextVar("gw_inbound_token", default=None)

NO_IDENTITY_MESSAGE = (
    "The gateway could not determine who is calling, so it refused to contact "
    "any upstream server. This is a gateway bug, not a permissions problem. "
    "Nothing was read."
)


def is_no_identity(exc: BaseException) -> bool:
    """The refusal current_inbound_token raises when a request carries no caller."""
    return isinstance(exc, ToolError) and str(exc) == NO_IDENTITY_MESSAGE


def set_inbound_token(token: AccessToken | None) -> object:
    return _INBOUND.set(token)


def reset_inbound_token(token: object) -> None:
    _INBOUND.reset(token)  # type: ignore[arg-type]


def current_inbound_token() -> AccessToken:
    """The validated inbound token, or raise.

    Never falls back to a process-global "last seen" token: that would be a
    cross-user leak. Fail-unknown, loudly.
    """
    token = _INBOUND.get() or get_access_token()
    if token is None or not getattr(token, "token", None):
        raise ToolError(NO_IDENTITY_MESSAGE)
    return token


def user_message(up: UpstreamConfig, exc: OBOError) -> str:
    """What the caller reads. Ours, not Entra's raw diagnostic.

    Every branch says what happened, what to do, and that nothing was read --
    because a refusal that reads like a bug generates a ticket.
    """
    tail = f" (Entra correlation id {exc.correlation_id})" if exc.correlation_id else ""
    if exc.kind == "step_up":
        return (
            f"Conditional Access wants you to complete a sign-in step for "
            f"{up.name} specifically. The gateway cannot do that on your behalf. "
            f"Disconnect and reconnect the gateway connector and complete the "
            f"prompt. Nothing was read.{tail}"
        )
    if exc.kind == "not_consented":
        return (
            f"Gateway misconfiguration, not your permissions: the gateway app "
            f"has no consented delegated permission to {up.name}. An engineer "
            f"needs to pre-authorize the gateway on that server's app "
            f"registration. Nothing was read.{tail}"
        )
    if exc.kind == "not_assigned":
        return (
            f"You are not assigned to {up.name}, so Entra would not issue a "
            f"token for it. Ask to be added to that server's access group. Your "
            f"other namespaces are unaffected. Nothing was read.{tail}"
        )
    if exc.kind in ("bad_scope", "bad_assertion", "bad_secret"):
        return (
            f"The gateway could not obtain a token for {up.name} because of a "
            f"configuration problem on our side ({exc.kind}). An engineer needs "
            f"to look at the gateway's Entra app. Nothing was read.{tail}"
        )
    if exc.kind == "entra_unreachable":
        return (
            f"The gateway could not reach Microsoft Entra to authorize a call to "
            f"{up.name}. This is usually transient; try again shortly. Nothing "
            f"was read.{tail}"
        )
    return (
        f"The gateway could not authorize a call to {up.name}: {exc.detail}. "
        f"Nothing was read.{tail}"
    )


def make_client_factory(
    up: UpstreamConfig, obo: OBOExchanger | None
) -> Callable[[], Awaitable[Client]]:
    """Build the zero-arg callable fastmcp invokes inside each request.

    `obo` is None only when inbound auth is disabled, which is the local
    development path. In that mode no token is obtained and none is forwarded;
    the upstream must itself be running with auth off.
    """

    async def client_factory() -> Client:
        # The Host header must name the PUBLIC hostname even though we connect
        # to a host:port on the docker host, because the token is audience-bound
        # to the public /mcp URL and some servers build their OAuth metadata
        # from the Host they receive. Safe to pass via headers=: the trap
        # documented above is specific to Authorization.
        headers = {"Host": up.host_header}

        if obo is None:
            transport = StreamableHttpTransport(url=up.url, headers=headers)
        else:
            inbound = current_inbound_token()  # raises rather than going anonymous
            try:
                token = await obo.token_for(
                    inbound.token, up.scope, upstream=up.name
                )
            except OBOError as exc:
                raise ToolError(user_message(up, exc)) from exc
            # auth=, NEVER headers= -- see the module docstring.
            transport = StreamableHttpTransport(
                url=up.url, headers=headers, auth=token
            )

        # Default is already False; set explicitly so the invariant is stated at
        # the point it matters and so tests can assert on it.
        transport.forward_incoming_headers = False
        return Client(
            transport, timeout=up.call_timeout, init_timeout=up.init_timeout
        )

    return client_factory


@dataclass(slots=True)
class Failure:
    reason: str
    user_message: str
    at: float

    def is_fresh(self, now: float) -> bool:
        return (now - self.at) < _FAILURE_TTL_S


def marker_tool(up: UpstreamConfig, failure: Failure) -> Tool:
    """A visible placeholder so a dead upstream is never silent.

    It is a LOCAL tool, not a ProxyTool: calling it returns the same explanation
    rather than attempting a connection. After the namespace transform it
    surfaces as e.g. inventory_unavailable.
    """
    text = failure.user_message

    async def unavailable() -> str:
        return text

    return Tool.from_function(
        fn=unavailable,
        name=MARKER_TOOL,
        title=f"{up.name}: UPSTREAM UNAVAILABLE",
        description=(
            f"{up.name} is not reachable from the gateway right now. "
            f"{text} Call this tool to see the current reason. No other "
            f"{up.namespace} tool will work until this clears."
        ),
        tags={"gateway", "unavailable", f"ns:{up.namespace}"},
    )


class ResilientProxyProvider(ProxyProvider):
    """One upstream, owning its own failure handling.

    A dead upstream degrades to a marker in the tool list rather than to
    silence, and never affects a sibling upstream: NamespaceOnce.get_tool short
    circuits on a name that does not carry this namespace's prefix, so a call
    routed elsewhere never touches this provider at all.
    """

    def __init__(
        self,
        up: UpstreamConfig,
        client_factory: Callable[[], Awaitable[Client]],
    ) -> None:
        super().__init__(client_factory=client_factory, cache_ttl=up.cache_ttl)
        self._up = up
        self._failure: Failure | None = None
        self._last_good: Sequence[Tool] = ()

    def __repr__(self) -> str:
        return f"ResilientProxyProvider({self._up.namespace!r} -> {self._up.name!r})"

    @property
    def upstream(self) -> UpstreamConfig:
        return self._up

    @property
    def failure(self) -> Failure | None:
        return self._failure

    def _record_failure(self, exc: BaseException) -> Failure:
        if isinstance(exc, ToolError):
            message = str(exc)
        elif isinstance(exc, OBOError):
            message = user_message(self._up, exc)
        else:
            message = (
                f"The gateway could not reach {self._up.name} "
                f"({type(exc).__name__}). Its other namespaces are unaffected. "
                f"Nothing was read."
            )
        failure = Failure(
            reason=f"{type(exc).__name__}: {exc}", user_message=message, at=time.monotonic()
        )
        self._failure = failure
        logger.warning(
            "upstream %s unavailable: %s", self._up.name, failure.reason
        )
        return failure

    async def _snapshot(self) -> tuple[Sequence[Tool], Failure | None]:
        """Fetch, or reuse a fresh failure rather than hammering a dead host."""
        now = time.monotonic()
        if self._failure is not None and self._failure.is_fresh(now):
            return self._last_good, self._failure
        try:
            tools = await super()._list_tools()
        # Per-item degradation: one upstream failing must not erase the answer
        # for the others. Every branch sets a visible marker, so this never
        # silently returns less than was asked for.
        except Exception as exc:  # noqa: BLE001 - see comment above
            if is_no_identity(exc):
                # About THIS request (no caller token: the boot-time listing, an
                # anonymous probe), not about the upstream. Caching it made every
                # real caller get "could not determine who is calling" for 30 s
                # after each redeploy (2026-11-18). Still a visible marker for
                # this request; never stored.
                return self._last_good, Failure(
                    reason=f"{type(exc).__name__}: {exc}", user_message=str(exc), at=now)
            return self._last_good, self._record_failure(exc)
        self._failure = None
        self._last_good = tools
        return tools, None

    async def _list_tools(self) -> Sequence[Tool]:
        tools, failure = await self._snapshot()
        if failure is not None:
            return [*tools, marker_tool(self._up, failure)]
        return tools

    async def _get_tool(
        self, name: str, version: VersionSpec | None = None
    ) -> Tool | None:
        tools, failure = await self._snapshot()
        if failure is not None:
            if name == MARKER_TOOL:
                return marker_tool(self._up, failure)
            if not tools:
                # No last-good metadata to resolve against. Raise the real
                # reason rather than letting this surface as "Unknown tool",
                # which reads like a bug and generates a ticket.
                raise ToolError(failure.user_message)
            return await super()._get_tool(name, version)
        return await super()._get_tool(name, version)
