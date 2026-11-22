"""Namespace authorization: who may see and call which upstream.

FIRST, THE THING THAT IS EASY TO GET WRONG. The per-server Entra group gate is
NOT replaced by this module. Because every upstream call carries a
user-delegated On-Behalf-Of token, Entra still refuses to mint that token for
someone not assigned to the upstream's enterprise app, exactly as today
(AADSTS50105). Each upstream's "Assignment required = Yes" plus its security
group REMAINS the security boundary, and because the gateway never holds an
app-only token it cannot become a confused deputy.

What this module adds is legibility and defense in depth. Without it every user
would see all namespaces and discover their lack of access as an Entra error
partway through a task.

Enforced in TWO places, because they have different jobs.

  (1) NamespaceGate, a Transform, stamps a per-tool AuthCheck onto everything an
      upstream provider yields. fastmcp runs component auth checks in BOTH
      FastMCP.list_tools() (filtering the list) and FastMCP._get_tool() (the
      resolution step inside call_tool), including the hashed-name bypass path.
      So a tool hidden this way is ALSO uncallable by name. That matters because
      BaseSearchTransform's own docstring says "Hidden tools remain callable --
      get_tool() delegates unknown names downstream", so hiding is not
      authorization.

  (2) NamespacePolicyMiddleware.on_call_tool runs BEFORE resolution and converts
      what (1) would otherwise produce -- "Unknown tool: inventory_list_hosts"
      -- into a sentence naming the group to ask for.

CORRECTION, measured 2026-09-10, because an earlier version of this docstring
said (2) was "only legibility" and that is wrong on the path that matters most.
With TOOL SEARCH on -- which is production -- tools/list returns three synthetic
tools and the real catalog is reached through search_tools. On that path BOTH
layers filter, INDEPENDENTLY: the search transform builds its index from the
auth-filtered catalog, which (1) filters via Tool.auth and (2) filters via
on_list_tools. tests/test_search_respects_policy.py proves it by removing each
in turn (search stays clean both times) and then both (mail tools leak to an
inventory-only user). So this is genuine defense in depth, not one guard plus a
message.

The user-visible consequence, which is the product requirement: a teammate does
not get "you cannot reach that tool". The tool is not in their search results at
all, so the model never learns its name and never calls it. The refusal text
below is a backstop for a caller who already knows a name -- a stale session, a
pasted tool name, or someone removed from a group mid-conversation -- and should
essentially never be seen in normal use.

Entitlement comes from APP ROLES on the gateway app (the `roles` claim), never a
raw `groups` claim: groups silently degrade to an overage pointer past roughly
150 memberships, and a gate that sees no groups is a gate that fails open.
Assign the EXISTING per-server groups to the gateway's app roles so there is one
membership list per server, not two.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware
from fastmcp.server.transforms import GetToolNext, Transform
from fastmcp.tools.base import Tool
from fastmcp.utilities.authorization import AuthContext
from fastmcp.utilities.versions import VersionSpec

from .naming import namespace_of

logger = logging.getLogger("mcp_gateway.policy")


def held_roles(token: AccessToken | None) -> frozenset[str]:
    """App roles in the caller's gateway token. Fails CLOSED and LOUD."""
    if token is None:
        return frozenset()
    claims = getattr(token, "claims", None) or {}
    roles = claims.get("roles")
    if roles is None and ("_claim_names" in claims or claims.get("hasgroups")):
        # The token carries a groups-overage pointer instead of app roles, which
        # means the gateway app was configured with groupMembershipClaims rather
        # than app roles. Do NOT guess and do NOT fall back to `groups`: deny
        # everything and make the misconfiguration visible.
        logger.error(
            "GATEWAY MISCONFIG: token carries a groups-overage pointer and no "
            "`roles` claim. The gateway app must expose app roles. Denying all "
            "namespaces rather than failing open."
        )
        return frozenset()
    return frozenset(str(r) for r in (roles or []))


def caller_label(token: AccessToken | None) -> str:
    """For logs. Identity only, never the token."""
    claims = (getattr(token, "claims", None) or {}) if token else {}
    return str(
        claims.get("preferred_username")
        or claims.get("upn")
        or claims.get("oid")
        or "anonymous"
    )


@dataclass(frozen=True)
class NamespacePolicy:
    """namespace -> the app role that grants it, and the group behind that role."""

    roles: Mapping[str, str]
    groups: Mapping[str, str]

    @property
    def known(self) -> frozenset[str]:
        return frozenset(self.roles)

    def namespace_of(self, tool_name: str) -> str | None:
        return namespace_of(tool_name, self.known)

    def entitled(self, token: AccessToken | None) -> frozenset[str]:
        held = held_roles(token)
        return frozenset(ns for ns, role in self.roles.items() if role in held)

    def denial(self, ns: str, tool_name: str, entitled: frozenset[str]) -> str:
        have = ", ".join(sorted(entitled)) or "no namespaces"
        group = self.groups.get(ns, f"the {ns} access group")
        return (
            f"{tool_name} belongs to the '{ns}' namespace, which requires the "
            f"'{self.roles[ns]}' app role on the gateway app, granted through "
            f"the {group} security group. Your sign-in carries: {have}. Ask an "
            f"admin to add you to {group}. Nothing about this call reached the "
            f"{ns} server."
        )


def namespace_gate(namespace: str, role: str):
    """Per-tool check. run_auth_checks masks unexpected exceptions into a
    denial, so this fails closed by construction as well as by intent."""

    def check(ctx: AuthContext) -> bool:
        return role in held_roles(ctx.token)

    check.__name__ = f"namespace_gate[{namespace}:{role}]"
    return check


class NamespaceGate(Transform):
    """Stamp one namespace's AuthCheck and tag onto everything below it.

    Added to the INNER provider with add_transform, while NamespaceOnce is
    applied around it. Order is safe: this changes only `auth` and `tags`, and
    the namespace transform's later model_copy(update={"name": ...}) carries
    both through.
    """

    def __init__(self, namespace: str, role: str) -> None:
        self._ns = namespace
        self._role = role
        self._check = namespace_gate(namespace, role)

    def __repr__(self) -> str:
        return f"NamespaceGate({self._ns!r}, role={self._role!r})"

    def _stamp(self, tool: Tool) -> Tool:
        existing = tool.auth
        checks = list(existing) if isinstance(existing, list) else ([existing] if existing else [])
        # A list, so a later check (read-only enforcement, say) can be ANDed on:
        # run_auth_checks uses AND semantics.
        return tool.model_copy(
            update={
                "auth": [*checks, self._check],
                "tags": set(tool.tags) | {f"ns:{self._ns}"},
            }
        )

    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        return [self._stamp(t) for t in tools]

    async def get_tool(
        self, name: str, call_next: GetToolNext, *, version: VersionSpec | None = None
    ) -> Tool | None:
        tool = await call_next(name, version=version)
        return None if tool is None else self._stamp(tool)


# Registered as a REAL tool on the server (see server._register_local_tools),
# not synthesized here. A tool that appears in tools/list but cannot be resolved
# by name raises "Unknown tool", which is exactly the reads-like-a-bug outcome
# this whole module exists to avoid. So the tool always exists and the
# middleware HIDES it from callers who do not need it, rather than conjuring it
# for callers who do.
NO_ACCESS_TOOL = "gw_no_access"


def no_access_message(policy: NamespacePolicy) -> str:
    groups = ", ".join(sorted(set(policy.groups.values()))) or "the access groups"
    return (
        "You are signed in to the gateway but are not a member of any server's "
        f"access group, so there is nothing to show. Ask an admin to add you to "
        f"one of: {groups}."
    )


class NamespacePolicyMiddleware(Middleware):
    """Legible refusals, one audit line per list, and a second filter where a
    wiring mistake in NamespaceGate would otherwise leak a name."""

    def __init__(self, policy: NamespacePolicy) -> None:
        self._policy = policy

    async def on_call_tool(self, context, call_next):
        name = getattr(context.message, "name", "")
        ns = self._policy.namespace_of(name)
        if ns is not None:
            token = get_access_token()
            entitled = self._policy.entitled(token)
            if ns not in entitled:
                logger.warning(
                    "DENY tools/call user=%s tool=%s ns=%s entitled=%s",
                    caller_label(token),
                    name,
                    ns,
                    sorted(entitled),
                )
                raise ToolError(self._policy.denial(ns, name, entitled))
        return await call_next(context)

    async def on_list_tools(self, context, call_next):
        tools = list(await call_next(context))
        token = get_access_token()
        entitled = self._policy.entitled(token)

        kept, dropped = [], []
        for tool in tools:
            if tool.name == NO_ACCESS_TOOL:
                # Kept only for a caller who is entitled to nothing; for anyone
                # else it is noise in every listing.
                if not entitled:
                    kept.append(tool)
                continue
            ns = self._policy.namespace_of(tool.name)
            ok = ns is None or ns in entitled
            (kept if ok else dropped).append(tool)

        if dropped:
            # Should be empty: NamespaceGate already filtered these at the
            # server layer. Non-empty means the transform is not wired to this
            # provider -- a bug, and one we must see rather than survive.
            logger.error(
                "POLICY BUG: %d tool(s) survived NamespaceGate and were dropped "
                "by middleware: %s",
                len(dropped),
                [t.name for t in dropped],
            )

        logger.info(
            "tools/list user=%s entitled=%s tools=%d",
            caller_label(token),
            sorted(entitled),
            len(kept),
        )
        return kept
