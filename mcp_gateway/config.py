"""Configuration, read from the environment exactly once at startup.

A half-configured server REFUSES TO START rather than starting and being subtly
wrong. A missing variable that silently falls back to a default is how a
container ends up serving unauthenticated, or talking to the wrong tenant, with
nothing in the logs to say so.

If you deploy with Docker Compose, every variable read here must also appear in
the compose file's `environment:` block. Compose only substitutes variables
into the file; it does not inject them into the container.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Namespaces must be lowercase alphanumeric with NO underscore, because the
# first underscore in a public tool name is the namespace separator
# (see naming.py). "helpdesk_get_summary" -> namespace "helpdesk". A namespace
# containing an underscore would make that parse ambiguous and silently
# misroute policy.
_NAMESPACE_OK = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")


class ConfigError(RuntimeError):
    """Configuration is missing or inconsistent. Always fatal at startup."""


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


@dataclass(frozen=True, slots=True)
class UpstreamConfig:
    """One backend MCP server.

    `url` is where we actually connect (often a host:port on a private network,
    not the public name). `host_header` is the PUBLIC hostname, sent
    explicitly, because the token we present is audience-bound to the public
    /mcp URL and some servers build their OAuth metadata from the Host header
    they receive. `identifier_uri` is that public /mcp URL: it is
    simultaneously the upstream's Entra Application ID URI and the audience of
    the token we must obtain.
    """

    name: str
    namespace: str
    url: str
    identifier_uri: str
    host_header: str
    scope: str
    # The Entra security group that grants this namespace, used ONLY to name it
    # in a refusal ("ask an admin to add you to X"). It must be the real name.
    # Group naming in a real tenant is rarely consistent, so a derived guess
    # like f"{namespace.capitalize()}-MCP-Users" sends people to a group that
    # does not exist. Passed in as GW_UP_<NS>_GROUP.
    group: str = ""
    call_timeout: float = 60.0
    init_timeout: float = 20.0
    # 300s matches fastmcp's own default. Pinned explicitly rather than left to
    # the library because a version bump must not change gateway behavior
    # quietly.
    #
    # Why not 0: ProxyProvider._list_tools() NEVER reads this cache -- every
    # tools/list is a live fetch with the calling user's own token. The cache is
    # read only by _get_tool() when resolving a call, and it holds tool METADATA
    # plus a shared zero-arg factory, never a token. So 0 would add a full
    # upstream listing plus a token exchange before every single tool call for
    # no security gain.
    #
    # REVISIT THIS if an upstream ever varies its tool LIST by caller identity.
    # A server that gates by caller inside the tool body at call time is fine.
    cache_ttl: float = 300.0


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """Inbound auth: validating the token Claude presents to US.

    Resource-server mode only (RemoteAuthProvider + AzureJWTVerifier). Never
    OAuth-proxy mode: in proxy mode a user's BROWSER must reach /authorize, so
    a reverse proxy that only admits the MCP client's egress would block your
    own staff.
    """

    enabled: bool
    tenant_id: str
    client_id: str
    identifier_uri: str
    base_url: str
    scope_name: str
    required_scopes: tuple[str, ...]
    advertise_offline_access: bool


@dataclass(frozen=True, slots=True)
class OBOConfig:
    """Outbound auth: exchanging that token for one per upstream.

    On-Behalf-Of requires a confidential client, so this is the one piece of
    the design that needs a CLIENT SECRET, with a rotation deadline to track.
    """

    tenant_id: str
    client_id: str
    client_secret: str
    cache_max_entries: int = 512
    http_timeout: float = 10.0

    @property
    def token_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"


@dataclass(frozen=True, slots=True)
class ServerConfig:
    transport: str
    host: str
    port: int
    path: str
    public_url: str
    # An unexpected Host header can produce a 421 that reads like a broken
    # container rather than an allowlist rejection. Recorded so a deployment
    # behind a reverse proxy can name the hosts it expects.
    allowed_hosts: tuple[str, ...]
    search_enabled: bool
    search_max_results: int
    log_level: str


@dataclass(frozen=True, slots=True)
class Config:
    server: ServerConfig
    auth: AuthConfig | None
    obo: OBOConfig | None
    upstreams: tuple[UpstreamConfig, ...] = field(default=())

    @property
    def namespaces(self) -> tuple[str, ...]:
        return tuple(u.namespace for u in self.upstreams)


def _validate_namespace(ns: str, where: str) -> str:
    if not ns:
        raise ConfigError(f"{where}: namespace is empty")
    bad = sorted(set(ns) - _NAMESPACE_OK)
    if bad:
        raise ConfigError(
            f"{where}: namespace {ns!r} may only contain lowercase letters and "
            f"digits (found {bad!r}). The first underscore in a tool name is "
            f"the namespace separator, so a namespace containing one would make "
            f"policy routing ambiguous."
        )
    return ns


def _validate_identifier_uri(uri: str, where: str) -> str:
    if not uri.startswith("https://"):
        raise ConfigError(f"{where}: identifier URI must be https, got {uri!r}")
    if not uri.endswith("/mcp"):
        raise ConfigError(
            f"{where}: identifier URI must be the server's /mcp URL, got {uri!r}. "
            f"This prevents AADSTS9010010: the Entra Application ID URI and the "
            f"advertised scope must both name the same /mcp URL. (The token's "
            f"aud claim itself comes back as the appId in v2; the verifier "
            f"accepts either form.)"
        )
    return uri


def load_upstreams() -> tuple[UpstreamConfig, ...]:
    """Read GATEWAY_UPSTREAMS and each GW_UP_<NS>_* group.

    GATEWAY_UPSTREAMS is a comma-separated list of namespaces, e.g.
    "inventory,docs,helpdesk". For each, these are read (all required except
    the optional ones noted):

        GW_UP_INVENTORY_URL             http://127.0.0.1:8101/mcp
        GW_UP_INVENTORY_IDENTIFIER_URI  https://inventory-mcp.example.com/mcp
        GW_UP_INVENTORY_NAME            inventory-mcp              (optional)
        GW_UP_INVENTORY_SCOPE           <identifier_uri>/.default  (optional)
        GW_UP_INVENTORY_HOST_HEADER     derived from identifier URI (optional)
        GW_UP_INVENTORY_GROUP           the access group's real name (optional)
    """
    raw = _env("GATEWAY_UPSTREAMS", "")
    names = [n.strip().lower() for n in (raw or "").split(",") if n.strip()]
    if not names:
        raise ConfigError(
            "GATEWAY_UPSTREAMS is empty. A gateway with no upstreams serves "
            "nothing; refusing to start rather than presenting an empty tool "
            "list that looks like a working connector."
        )

    seen: set[str] = set()
    out: list[UpstreamConfig] = []
    for ns in names:
        _validate_namespace(ns, "GATEWAY_UPSTREAMS")
        if ns in seen:
            raise ConfigError(f"GATEWAY_UPSTREAMS lists {ns!r} more than once")
        seen.add(ns)

        prefix = f"GW_UP_{ns.upper()}"
        url = _env(f"{prefix}_URL")
        identifier_uri = _env(f"{prefix}_IDENTIFIER_URI")
        if not url:
            raise ConfigError(f"{prefix}_URL is required (namespace {ns!r})")
        if not identifier_uri:
            raise ConfigError(f"{prefix}_IDENTIFIER_URI is required (namespace {ns!r})")
        _validate_identifier_uri(identifier_uri, prefix)

        host_header = _env(f"{prefix}_HOST_HEADER") or (
            urlparse(identifier_uri).hostname or ""
        )
        if not host_header:
            raise ConfigError(f"{prefix}: could not derive a Host header")

        out.append(
            UpstreamConfig(
                name=_env(f"{prefix}_NAME") or f"{ns}-mcp",
                namespace=ns,
                url=url,
                identifier_uri=identifier_uri,
                host_header=host_header,
                # ".default" asks for every delegated permission the gateway has
                # been granted on that upstream, which is what pre-authorization
                # sets up. An explicit ".../access_as_user" also works; .default
                # avoids a per-upstream scope-name assumption.
                scope=_env(f"{prefix}_SCOPE") or f"{identifier_uri}/.default",
                group=_env(f"{prefix}_GROUP") or "",
                call_timeout=_env_float(f"{prefix}_CALL_TIMEOUT", 60.0),
                init_timeout=_env_float(f"{prefix}_INIT_TIMEOUT", 20.0),
                cache_ttl=_env_float(f"{prefix}_CACHE_TTL", 300.0),
            )
        )
    return tuple(out)


def load_auth() -> AuthConfig | None:
    """Inbound auth. Returns None ONLY when explicitly disabled.

    MCP_AUTH_ENABLED=false is for local development against MCP Inspector and
    Claude Code. Never expose an auth-off gateway: it would front every upstream
    with no identity at all.
    """
    if not _env_bool("MCP_AUTH_ENABLED", True):
        return None

    tenant_id = _env("ENTRA_TENANT_ID")
    client_id = _env("ENTRA_CLIENT_ID")
    identifier_uri = _env("ENTRA_IDENTIFIER_URI")
    base_url = _env("MCP_BASE_URL")
    missing = [
        n
        for n, v in (
            ("ENTRA_TENANT_ID", tenant_id),
            ("ENTRA_CLIENT_ID", client_id),
            ("ENTRA_IDENTIFIER_URI", identifier_uri),
            ("MCP_BASE_URL", base_url),
        )
        if not v
    ]
    if missing:
        raise ConfigError(
            "MCP_AUTH_ENABLED is true but these are unset: "
            + ", ".join(missing)
            + ". Refusing to start rather than serving unauthenticated."
        )
    assert tenant_id and client_id and identifier_uri and base_url
    _validate_identifier_uri(identifier_uri, "ENTRA_IDENTIFIER_URI")

    scope_name = _env("ENTRA_SCOPE_NAME", "access_as_user") or "access_as_user"
    required = tuple(
        s.strip()
        for s in (_env("ENTRA_REQUIRED_SCOPES", scope_name) or "").split(",")
        if s.strip()
    )
    return AuthConfig(
        enabled=True,
        tenant_id=tenant_id,
        client_id=client_id,
        identifier_uri=identifier_uri,
        base_url=base_url.rstrip("/"),
        scope_name=scope_name,
        required_scopes=required,
        advertise_offline_access=_env_bool("ENTRA_ADVERTISE_OFFLINE_ACCESS", True),
    )


def load_obo(auth: AuthConfig | None) -> OBOConfig | None:
    """Outbound auth. Required whenever inbound auth is on.

    A gateway that validates a user but then cannot obtain an upstream token is
    useless, so this is fatal rather than degraded: without it every tool call
    would fail at the first upstream, which looks like a broken fleet.
    """
    if auth is None:
        return None

    secret = _env("ENTRA_GATEWAY_CLIENT_SECRET")
    if not secret:
        raise ConfigError(
            "ENTRA_GATEWAY_CLIENT_SECRET is required when MCP_AUTH_ENABLED is "
            "true. On-Behalf-Of needs a confidential client. Refusing to start: "
            "a gateway that cannot exchange tokens fails every tool call, which "
            "is indistinguishable from every upstream being down."
        )
    if "$" in secret:
        # Compose performs its own variable expansion on values it substitutes,
        # so a $ in a secret is read as an undefined variable and silently
        # deleted. The app then starts cleanly and every exchange fails, which
        # reads as "the password does not work" for hours.
        raise ConfigError(
            "ENTRA_GATEWAY_CLIENT_SECRET contains '$', which Compose will expand "
            "away when it travels through a stack variable. Regenerate the "
            "secret until it has none."
        )
    return OBOConfig(
        tenant_id=auth.tenant_id,
        client_id=auth.client_id,
        client_secret=secret,
        cache_max_entries=_env_int("ENTRA_OBO_CACHE_MAX", 512),
        http_timeout=_env_float("ENTRA_OBO_TIMEOUT", 10.0),
    )


def load_server(auth: AuthConfig | None) -> ServerConfig:
    path = _env("MCP_PATH", "/mcp") or "/mcp"
    if not path.startswith("/"):
        raise ConfigError(f"MCP_PATH must start with '/', got {path!r}")

    public_url = _env("MCP_PUBLIC_URL") or (auth.base_url if auth else "")
    hosts: list[str] = []
    if public_url:
        hostname = urlparse(public_url).hostname
        if hostname:
            hosts.append(hostname)
    hosts.extend(
        h.strip() for h in (_env("EXTRA_ALLOWED_HOSTS", "") or "").split(",") if h.strip()
    )

    return ServerConfig(
        transport=_env("MCP_TRANSPORT", "http") or "http",
        host=_env("MCP_HOST", "0.0.0.0") or "0.0.0.0",
        port=_env_int("MCP_PORT", 8000),
        path=path,
        public_url=public_url,
        allowed_hosts=tuple(dict.fromkeys(hosts)),
        # Tool search collapses the catalog to search_tools + call_tool. On by
        # default: with a dozen or more upstreams a flat list is a couple of
        # hundred tool schemas re-sent on every turn, which is a bigger context
        # bill than the servers cost separately. Off is useful for measuring
        # exactly that.
        search_enabled=_env_bool("GATEWAY_TOOL_SEARCH", True),
        search_max_results=_env_int("GATEWAY_TOOL_SEARCH_MAX_RESULTS", 8),
        log_level=(_env("LOG_LEVEL", "INFO") or "INFO").upper(),
    )


def load() -> Config:
    """Build the whole configuration, or raise ConfigError. Never partial."""
    auth = load_auth()
    return Config(
        server=load_server(auth),
        auth=auth,
        obo=load_obo(auth),
        upstreams=load_upstreams(),
    )
