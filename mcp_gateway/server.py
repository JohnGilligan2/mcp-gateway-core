"""The gateway server: assembly, auth, health, and main().

Deliberately does NOT use create_proxy()/FastMCPProxy, for two reasons:
  * both force forward_incoming_headers = True on the upstream client, which is
    exactly the token passthrough the specification forbids;
  * FastMCPProxy opens an upstream connection during initialize, which would
    force a token exchange before the client has listed anything and turn one
    upstream outage into a failed handshake for the whole gateway.

So: FastMCP(...) + add_provider(ResilientProxyProvider(...)) per upstream.
"""

from __future__ import annotations

import logging
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.azure import AzureJWTVerifier
from fastmcp.server.middleware import Middleware
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse

from . import __version__, redact
from .config import Config, UpstreamConfig, load
from .naming import NamespaceOnce
from .obo import OBOExchanger
from .policy import (
    NO_ACCESS_TOOL,
    NamespaceGate,
    NamespacePolicy,
    NamespacePolicyMiddleware,
    no_access_message,
)
from .upstreams import (
    MARKER_TOOL,
    ResilientProxyProvider,
    make_client_factory,
    reset_inbound_token,
    set_inbound_token,
)

logger = logging.getLogger("mcp_gateway.server")

SERVICE_NAME = "mcp-gateway"


def build_auth(cfg: Config) -> RemoteAuthProvider | None:
    """Inbound auth in RESOURCE-SERVER mode only.

    The server VALIDATES audience-bound v2 JWTs; it never issues them. The user
    signs in directly at Microsoft and only the MCP client's cloud calls us, so
    a reverse proxy in front can keep an egress allowlist. OAuth-proxy mode
    (AzureProvider) would require staff browsers to reach /authorize and force
    that allowlist open.
    """
    if cfg.auth is None:
        logger.warning(
            "MCP_AUTH_ENABLED is false. This is for local development only: an "
            "exposed gateway with auth off fronts every upstream with no "
            "identity at all."
        )
        return None

    a = cfg.auth
    verifier = AzureJWTVerifier(
        tenant_id=a.tenant_id,
        client_id=a.client_id,
        identifier_uri=a.identifier_uri,
        required_scopes=list(a.required_scopes) or None,
    )
    # FULL-URL scope, not the bare name: advertising `access_as_user` alone is
    # what produces AADSTS70011 at sign-in.
    scopes = [f"{a.identifier_uri}/{a.scope_name}"]
    if a.advertise_offline_access:
        # Without offline_access the client never obtains a refresh token and
        # the connector dies quietly when the ~60-90 minute access token expires.
        scopes.append("offline_access")

    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[
            AnyHttpUrl(f"https://login.microsoftonline.com/{a.tenant_id}/v2.0")
        ],
        base_url=a.base_url,
        scopes_supported=scopes,
    )


class TokenCaptureMiddleware(Middleware):
    """Stash the validated inbound token in a ContextVar for the whole request.

    The proxy's client_factory can reach the token via get_access_token()
    directly (verified by execution on both the list and call paths under
    stateless_http=True). This is belt and braces against a future move off
    stateless mode, where the session task would carry a stale context.
    """

    async def on_message(self, context, call_next):
        from fastmcp.server.dependencies import get_access_token

        token = None
        try:
            token = get_access_token()
        except Exception:  # noqa: BLE001
            # Swallowed: an unauthenticated path (auth disabled, or a request
            # that has not reached auth yet) legitimately has no token. Callers
            # that REQUIRE one raise their own error rather than proceeding
            # anonymously -- see upstreams.current_inbound_token.
            token = None
        marker = set_inbound_token(token)
        try:
            return await call_next(context)
        finally:
            reset_inbound_token(marker)


def build_policy(cfg: Config) -> NamespacePolicy | None:
    """Namespace-to-app-role mapping, or None when inbound auth is off.

    With auth off there is no token, so every gate would deny and the local
    bench would serve nothing. Policy is therefore tied to auth being on.
    """
    if cfg.auth is None:
        return None
    roles = {u.namespace: f"{u.namespace}.read" for u in cfg.upstreams}
    # Real group names, supplied per upstream. NOT derived: a derived guess
    # would send people to a group that does not exist, which is worse than
    # saying nothing. Fall back to a generic phrase rather than inventing a
    # plausible-looking wrong name.
    groups = {
        u.namespace: (u.group or f"the {u.namespace} access group")
        for u in cfg.upstreams
    }
    missing = [u.namespace for u in cfg.upstreams if not u.group]
    if missing:
        logger.warning(
            "no GW_UP_<NS>_GROUP set for %s; refusals for those namespaces will "
            "not name a group to ask for",
            ", ".join(sorted(missing)),
        )
    return NamespacePolicy(roles=roles, groups=groups)


def build_provider(
    up: UpstreamConfig, obo: Any, policy: NamespacePolicy | None
) -> tuple[ResilientProxyProvider, Any]:
    """One upstream: proxy provider, optional per-tool gate, namespace on top.

    Returns both the inner provider (so the caller keeps a handle for status)
    and the wrapped one that gets registered. The wrapper delegates to the
    inner's PUBLIC list_tools, so the inner's own transforms run first: gate,
    then namespace.

    `obo` is anything with `async token_for(inbound, scope, *, upstream)`:
    OBOExchanger in production, a stub in tests and the example.
    """
    provider = ResilientProxyProvider(up, make_client_factory(up, obo))
    if policy is not None:
        # Inner: stamps the AuthCheck that fastmcp enforces on BOTH the list and
        # the get path, so a hidden tool is genuinely uncallable.
        provider.add_transform(NamespaceGate(up.namespace, policy.roles[up.namespace]))
    # Outer: prefix once. Returns a NEW provider; the original is not mutated.
    return provider, provider.wrap_transform(NamespaceOnce(up.namespace))


def add_tool_search(mcp: FastMCP, namespaces, max_results: int = 8) -> None:
    """Replace the flat catalog with search_tools + call_tool.

    The unavailable markers MUST stay visible. Search hides everything it does
    not pin, and a marker nobody can see is exactly the silent degradation this
    design refuses: the tool list would look healthy while a whole namespace
    was dead. Their names are known at build time because they are derived from
    the configured namespaces.
    """
    from fastmcp.server.transforms.search.bm25 import BM25SearchTransform

    pinned = ["gw_status", *(f"{ns}_{MARKER_TOOL}" for ns in namespaces)]
    mcp.add_transform(BM25SearchTransform(max_results=max_results, always_visible=pinned))


def build_server(cfg: Config, *, obo: Any = None, auth: Any = None) -> FastMCP:
    """Assemble the gateway.

    `obo` and `auth` default to the real Entra pieces built from `cfg`; tests
    and the example pass stubs so the whole assembly runs offline.
    """
    if auth is None:
        auth = build_auth(cfg)
    policy = build_policy(cfg)

    if obo is None and cfg.obo is not None:
        obo = OBOExchanger(
            tenant_id=cfg.obo.tenant_id,
            client_id=cfg.obo.client_id,
            client_secret=cfg.obo.client_secret,
            max_entries=cfg.obo.cache_max_entries,
            timeout=cfg.obo.http_timeout,
        )

    # Order matters, and fastmcp wraps outside-in: the FIRST entry is the
    # outermost, so it sees the final result after everything inner has run.
    #
    #   TokenCapture stashes the caller for the proxy client factory.
    #   Policy      filters the catalog and makes refusals legible.
    #   Collision   innermost, inspecting the aggregated catalog.
    middleware: list[Middleware] = [TokenCaptureMiddleware()]
    if policy is not None:
        middleware.append(NamespacePolicyMiddleware(policy))
    middleware.append(CollisionGuardMiddleware())

    mcp: FastMCP = FastMCP(
        name=SERVICE_NAME,
        version=__version__,
        auth=auth,
        middleware=middleware,
        instructions=(
            "One endpoint fronting several MCP servers. Tool names are "
            "namespaced by server: a tool beginning `inventory_` runs against "
            "the inventory server, `docs_` against the documentation server, "
            "and so on. A tool named `<namespace>_unavailable` means that "
            "server is unreachable right now; call it to see why. Call "
            "`gw_status` to see every server's reachability and which "
            "namespaces you are entitled to."
        ),
    )

    # "raise" rather than the inherited default of "warn". The default logs a
    # warning and silently drops a failed provider's ENTIRE tool list, which is
    # a silent partial result. Each provider already catches its own expected
    # failures and degrades to a visible marker tool, so anything still
    # reaching the aggregate is a genuine bug and must be loud. Set as an
    # attribute because FastMCP inherits it from AggregateProvider and does not
    # accept it as a constructor argument in 3.4.5.
    mcp.provider_error_strategy = "raise"

    proxies: list[ResilientProxyProvider] = []
    for up in cfg.upstreams:
        inner, wrapped = build_provider(up, obo, policy)
        proxies.append(inner)
        mcp.add_provider(wrapped)
    # Keep our own handles rather than unwrapping fastmcp's private
    # _WrappedProvider._inner at runtime. Same objects, no dependency on an
    # internal attribute name that a version bump could rename.
    mcp.gateway_proxies = proxies  # type: ignore[attr-defined]

    if cfg.server.search_enabled:
        # Safe alongside the policy gate: search results respect component auth
        # checks, and the call path routes through the server's own call_tool.
        # tests/test_search_respects_policy.py holds that to account.
        add_tool_search(mcp, cfg.namespaces, cfg.server.search_max_results)

    _register_local_tools(mcp, cfg, policy)
    _register_health(mcp, cfg, obo)
    return mcp


def _register_local_tools(
    mcp: FastMCP, cfg: Config, policy: NamespacePolicy | None
) -> None:
    if policy is not None:
        message = no_access_message(policy)

        @mcp.tool(
            name=NO_ACCESS_TOOL,
            description=(
                "Explains why no server tools are available to you. Shown only "
                "when your sign-in grants access to none of them."
            ),
        )
        async def gw_no_access() -> str:
            # A REAL tool, hidden by the policy middleware for anyone who has
            # access to something. Synthesizing it in the middleware instead
            # produced a tool that listed but could not be called, which raises
            # "Unknown tool" and reads exactly like the bug this avoids.
            return message

    @mcp.tool(
        name="gw_status",
        description=(
            "ANSWERS 'what tools do I have', 'what can I do here', 'what "
            "servers can I reach', 'why is a tool missing', and 'is a server "
            "down'. Call this FIRST for any question about available "
            "capability. Returns the signed-in user's own servers and the full "
            "list of tool names they can use, which is the complete answer - "
            "searching with an empty query is not."
        ),
    )
    async def gw_status() -> dict[str, Any]:
        # WHY THIS LISTS TOOL NAMES. With tool search on, tools/list returns
        # only search_tools + call_tool + this, so a client asked "what tools do
        # I have" has nothing to read. And it cannot fall back to an empty
        # search: BM25 scores against query terms, so search_tools("") returns
        # ZERO results, which would read as "you have nothing".
        #
        # Names only, never schemas. The whole point of tool search is not
        # paying for every schema on every turn; a name list is a few hundred
        # bytes on one call.
        from fastmcp.server.dependencies import get_access_token

        from .naming import public_name
        from .policy import caller_label

        token = get_access_token() if cfg.auth else None
        entitled = set(policy.entitled(token)) if policy else set(cfg.namespaces)

        servers = []
        total = 0
        for provider in _proxy_providers(mcp):
            up = provider.upstream
            if up.namespace not in entitled:
                # Not merely unlisted: absent. A caller must not learn that a
                # namespace they cannot use exists, or the next question is
                # "why can't I have that one".
                continue
            failure = provider.failure
            try:
                tools, failure = await provider._snapshot()
                names = sorted(public_name(up.namespace, t.name) for t in tools)
            except Exception:  # noqa: BLE001
                # Swallowed per server, and loudly: one unreachable upstream
                # must not empty the whole answer, and the entry below says
                # "reachable: false" rather than pretending it has no tools.
                names = []
                failure = failure or provider.failure
            total += len(names)
            servers.append(
                {
                    "namespace": up.namespace,
                    "server": up.name,
                    "tool_prefix": f"{up.namespace}_",
                    "reachable": failure is None,
                    "problem": failure.user_message if failure else None,
                    "tool_count": len(names),
                    "tools": names,
                }
            )

        out: dict[str, Any] = {
            "gateway": SERVICE_NAME,
            "gateway_version": __version__,
            "you": caller_label(token) if cfg.auth else "(auth disabled)",
            "your_servers": [s["server"] for s in servers],
            "total_tools_available_to_you": total,
            "servers": servers,
        }
        if not servers:
            out["note"] = (
                "You are signed in but are not a member of any server's access "
                "group, so there is nothing available. Ask an admin to add you."
            )
        else:
            out["how_to_use"] = (
                "Call search_tools with a description of the task to get the "
                "full definition of a matching tool, then call it by name. "
                "Only the tools listed here exist for this user."
            )
        return out


def _proxy_providers(mcp: FastMCP) -> list[ResilientProxyProvider]:
    """The gateway's own upstream providers, kept aside at build time."""
    return list(getattr(mcp, "gateway_proxies", []) or [])


def _register_health(mcp: FastMCP, cfg: Config, obo: Any) -> None:
    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> JSONResponse:
        import fastmcp

        return JSONResponse(
            {
                "status": "ok",
                "service": SERVICE_NAME,
                "version": __version__,
                # Reported so image drift is visible from outside the container.
                # A floating pin once changed connector session behavior on a
                # rebuild with nothing to show for it; this makes that legible.
                "fastmcp": getattr(fastmcp, "__version__", "unknown"),
                "auth_enabled": cfg.auth is not None,
                "obo_enabled": obo is not None,
                "upstreams": len(cfg.upstreams),
                "namespaces": list(cfg.namespaces),
                "tool_search": cfg.server.search_enabled,
            }
        )


# THERE IS NO BOOT-TIME COLLISION SWEEP, AND THAT IS DELIBERATE. Two reasons,
# both measured rather than assumed:
#
#   1. It cannot work in production. With inbound auth on there is no caller at
#      boot, so the client factory correctly refuses to contact any upstream and
#      the sweep enumerates NOTHING.
#   2. Attempting it broke startup. Run before mcp.run() in its own
#      asyncio.run(), or inside a custom lifespan, uvicorn reported "Waiting for
#      application startup" and never completed. NOT ROOT-CAUSED -- recorded
#      here so the next person does not rediscover it by reintroducing it.
#
# The protection that actually matters is CollisionGuardMiddleware, which runs
# on a real tools/list with a real token and refuses to serve an ambiguous
# catalog. assert_no_collisions() remains the shared checker, exercised directly
# by tests/test_naming.py.


class CollisionGuardMiddleware(Middleware):
    """Refuse to serve an ambiguous tool list. The real collision defense.

    fastmcp will not do this for us: AggregateProvider only WARNS on a duplicate
    component key and returns both, and its source says an errorable mode was
    rejected on purpose. The wire handler then dedupes by name and the call path
    resolves by version sort, which is arbitrary among unversioned tools.
    Across two customers' servers an arbitrary route is a data disclosure.

    So: if two tools would be published under one name, fail the listing loudly
    rather than hand over a catalog where one name means two things. That is a
    visibly broken connector instead of a quietly wrong one.
    """

    async def on_list_tools(self, context, call_next):
        tools = list(await call_next(context))
        seen: dict[str, int] = {}
        for tool in tools:
            seen[tool.name] = seen.get(tool.name, 0) + 1
        duplicates = sorted(name for name, n in seen.items() if n > 1)
        if duplicates:
            logger.error(
                "TOOL NAME COLLISION at runtime: %s. Refusing to serve an "
                "ambiguous catalog.",
                duplicates,
            )
            raise ToolError(
                "The gateway is serving two different tools under the same "
                f"name(s): {', '.join(duplicates)}. It refuses to continue, "
                "because resolving one of these calls would pick a server "
                "essentially at random. An engineer needs to give the "
                "upstreams distinct namespaces. Nothing was read."
            )
        return tools


def main() -> None:
    cfg = load()
    redact.install(cfg.server.log_level)
    logger.info(
        "%s %s starting: %d upstream(s) %s, auth=%s, tool_search=%s",
        SERVICE_NAME,
        __version__,
        len(cfg.upstreams),
        list(cfg.namespaces),
        cfg.auth is not None,
        cfg.server.search_enabled,
    )
    if cfg.server.allowed_hosts:
        logger.info("allowed hosts: %s", list(cfg.server.allowed_hosts))

    mcp = build_server(cfg)

    # NOTHING ASYNC MAY RUN BEFORE mcp.run(). See the block above
    # CollisionGuardMiddleware: an asyncio.run() here, or a lifespan that
    # touched the providers, both left uvicorn stuck at "Waiting for application
    # startup" forever.

    if cfg.server.transport == "stdio":
        mcp.run()
        return

    mcp.run(
        transport=cfg.server.transport,
        host=cfg.server.host,
        port=cfg.server.port,
        path=cfg.server.path,
        # Redeploys otherwise strand every live session, and stateless mode is
        # also what makes the request context reliable inside the proxy's
        # client factory.
        stateless_http=True,
    )
