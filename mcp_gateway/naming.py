"""Tool naming: prefix once, and refuse to boot on a collision.

Two problems, one cosmetic and one that is a data-disclosure risk.

COSMETIC. fastmcp's Namespace transform prepends its prefix unconditionally, so
an upstream that already self-prefixes its tools (docs_*, mail_* and so on)
comes out as docs_docs_capabilities.
That is paid for in every tool list and reads to the model like a bug.

SERIOUS. Un-namespaced collisions route ARBITRARILY. fastmcp's AggregateProvider
only logs a warning on a duplicate component key and returns BOTH entries; the
wire handler then dedupes by name and the call path picks one by version sort,
which is arbitrary among unversioned tools. In the fleet this came from, two
per-customer phone servers built from one template shared eleven bare tool
names -- list_devices, list_domains, list_users, get_recording_link among
them -- and they were two DIFFERENT CUSTOMERS' systems. An arbitrary route
there is a cross-customer disclosure, so namespacing is mandatory and a
collision is a startup failure, not a warning.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from fastmcp.server.transforms import GetPromptNext, GetToolNext
from fastmcp.server.transforms.namespace import Namespace
from fastmcp.utilities.versions import VersionSpec

logger = logging.getLogger("mcp_gateway.naming")


class CollisionError(RuntimeError):
    """Two upstreams would publish the same public tool name. Always fatal."""


class NamespaceOnce(Namespace):
    """Namespace, except it does not re-prefix an already-prefixed name.

    Keeps docs_capabilities as docs_capabilities instead of
    docs_docs_capabilities, while still turning the inventory server's bare
    list_hosts into inventory_list_hosts.

    The reverse direction has to try both spellings, because after this
    transform a public name may or may not have been rewritten. Trying the
    stripped form first and the raw form second costs nothing at runtime: both
    resolve against the provider's already-populated tool cache.
    """

    def _transform_name(self, name: str) -> str:
        if name == self._prefix or name.startswith(self._name_prefix):
            return name
        return super()._transform_name(name)

    async def _resolve(self, name: str, call_next, *, version):
        # Short-circuit: a name that does not carry our prefix belongs to some
        # other upstream. Returning immediately means a DEAD upstream cannot
        # slow down or break a call routed to a healthy one -- per-upstream
        # isolation on the call path is structural, not best-effort.
        if name != self._prefix and not name.startswith(self._name_prefix):
            return None
        stripped = self._reverse_name(name)
        candidates = [c for c in (stripped, name) if c]
        for candidate in candidates:
            found = await call_next(candidate, version=version)
            if found is not None:
                return found.model_copy(update={"name": name})
        return None

    async def get_tool(
        self, name: str, call_next: GetToolNext, *, version: VersionSpec | None = None
    ):
        return await self._resolve(name, call_next, version=version)

    async def get_prompt(
        self, name: str, call_next: GetPromptNext, *, version: VersionSpec | None = None
    ):
        return await self._resolve(name, call_next, version=version)

    async def list_tools(self, tools: Sequence):
        return [t.model_copy(update={"name": self._transform_name(t.name)}) for t in tools]

    async def list_prompts(self, prompts: Sequence):
        return [
            p.model_copy(update={"name": self._transform_name(p.name)}) for p in prompts
        ]

    def __repr__(self) -> str:
        return f"NamespaceOnce({self._prefix!r})"


def public_name(namespace: str, tool_name: str) -> str:
    """The name a client will see for `tool_name` coming from `namespace`."""
    prefix = f"{namespace}_"
    if tool_name == namespace or tool_name.startswith(prefix):
        return tool_name
    return f"{prefix}{tool_name}"


def namespace_of(tool_name: str, known: frozenset[str] | set[str]) -> str | None:
    """Which namespace a public tool name belongs to, or None for a local tool.

    Exact head lookup, never prefix matching: config.py guarantees namespaces
    contain no underscore, which is what makes the first underscore an
    unambiguous separator.
    """
    head, sep, rest = tool_name.partition("_")
    if sep and rest and head in known:
        return head
    return None


def assert_no_collisions(catalogs: dict[str, Sequence[str]]) -> None:
    """Refuse to boot if two distinct upstream tools map to one public name.

    `catalogs` maps namespace -> that upstream's raw tool names.

    Two ways a clash can happen, and the second is the one that actually bites.

    ACROSS namespaces. Rare, because prefixing normally separates everything --
    it takes a tool whose raw name already begins with ANOTHER namespace's
    prefix. This is what stops an un-namespaced configuration slipping through.

    WITHIN one namespace, caused by prefix-once itself. A server exposing both
    `capabilities` and `docs_capabilities` has both collapse onto
    `docs_capabilities`. That is a hazard this module's own optimization
    introduces, so this module has to catch it.

    Either way fastmcp will not help: AggregateProvider only WARNS on a
    duplicate key and returns both, and its source says an errorable mode was
    rejected deliberately. The call then resolves to whichever the version sort
    picks, which is arbitrary among unversioned tools. So the check has to be
    here, and it has to be fatal at startup: a container that will not come up
    with the reason in its logs beats a running gateway that silently routes
    some calls to the wrong server.
    """
    owners: dict[str, set[tuple[str, str]]] = {}
    for namespace, tools in catalogs.items():
        for tool in tools:
            owners.setdefault(public_name(namespace, tool), set()).add((namespace, tool))

    clashes = {name: sorted(src) for name, src in owners.items() if len(src) > 1}
    if clashes:
        detail = "; ".join(
            f"{name!r} <- " + ", ".join(f"{ns}:{raw}" for ns, raw in sources)
            for name, sources in sorted(clashes.items())
        )
        raise CollisionError(
            f"{len(clashes)} tool name collision(s): {detail}. Refusing to "
            f"start. A duplicate is not cosmetic: fastmcp only warns and then "
            f"resolves the call to an arbitrary source, which across two "
            f"customers' servers is a data disclosure. Fix by giving the "
            f"upstreams distinct namespaces, or by renaming the offending tool "
            f"upstream."
        )

    logger.info(
        "naming preflight ok: %d public tool names across %d namespaces",
        len(owners),
        len(catalogs),
    )
