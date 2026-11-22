"""Hand-rolled Entra On-Behalf-Of exchange.

fastmcp 3.4.5 ships an OBO helper (fastmcp/server/auth/providers/azure.py, class
_EntraOBOToken) and it CANNOT be used here, for two independent reasons read out
of that file:

  1. __aenter__ calls _require_azure_identity(); azure-identity is not installed
     and is deliberately not in requirements.txt.
  2. It calls _find_azure_provider(server.auth) and raises unless the auth
     provider is an AzureProvider -- which is OAuth-proxy mode. This gateway
     must stay in resource-server mode (RemoteAuthProvider + AzureJWTVerifier)
     so a reverse proxy can admit only the MCP client's egress addresses,
     because in proxy mode a user's browser must reach /authorize. That check
     can never pass.

So we POST the jwt-bearer grant ourselves. ONE round trip per (user token,
upstream) per token lifetime, because the cache below stores the in-flight
asyncio.Task rather than its result: a dozen tools fanning out across three
upstreams must not become three dozen calls to Entra.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Final

import httpx

logger = logging.getLogger("mcp_gateway.obo")

GRANT_TYPE: Final = "urn:ietf:params:oauth:grant-type:jwt-bearer"

# Subtracted from the lifetime Entra reports. An OBO access token is good for
# roughly an hour; 120s covers clock skew plus the slowest upstream call we are
# willing to START with a token this old.
_EXPIRY_MARGIN_S: Final = 120.0
# Floor, so a pathologically short token is still cached for one fan-out rather
# than re-fetched per tool call.
_MIN_TTL_S: Final = 30.0
# A deterministic refusal is remembered briefly so a 12-tool fan-out produces
# one rejection rather than twelve. Short enough that an admin who fixes an
# assignment sees it work almost immediately. Note a user who re-consents gets a
# NEW inbound token, whose hash is a different key, so re-auth is never blocked.
_NEGATIVE_TTL_S: Final = 30.0
# Placeholder lifetime while an exchange is in flight. Anything shorter than the
# exchange itself would let a second caller start a duplicate.
_PROVISIONAL_TTL_S: Final = 60.0

_AADSTS_RE: Final = re.compile(r"AADSTS(\d{4,7})")

# UNVERIFIED against a live tenant -- taken from Entra's published error list.
# Anything absent classifies as "unknown", which still denies loudly. Correct
# this table from the first real refusal rather than trusting it.
_KIND_BY_CODE: Final = {
    "50076": "step_up",  # Conditional Access requires MFA for this resource
    "50079": "step_up",  # MFA enrollment required
    "50158": "step_up",  # external CA / claims challenge
    "65001": "not_consented",  # gateway not pre-authorized for the upstream
    "50105": "not_assigned",  # user not assigned to the upstream's app
    "70011": "bad_scope",  # invalid scope value (App ID URI drift)
    "500011": "bad_scope",  # resource principal not found in tenant
    "50013": "bad_assertion",
    "500131": "bad_assertion",
    "700082": "bad_assertion",  # assertion expired
    "7000215": "bad_secret",  # invalid client secret
    "7000222": "bad_secret",  # EXPIRED client secret
}

# Kinds the operator must fix, as opposed to the user. Logged at ERROR.
_OPERATOR_FAULT: Final = frozenset(
    {"not_consented", "bad_scope", "bad_secret", "bad_assertion"}
)


class OBOError(RuntimeError):
    """An exchange that failed in a way somebody has to be told about.

    Carries the classification rather than only the text, because the gateway
    reacts differently per kind and because the user-facing sentence must be
    ours, not Entra's raw diagnostic.
    """

    def __init__(
        self,
        kind: str,
        upstream: str,
        detail: str,
        *,
        aadsts: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        # SCRUB AT CONSTRUCTION, not at the point of display. Entra echoes the
        # submitted assertion back in some error descriptions (AADSTS500131 and
        # friends), and `detail` reaches a user-facing refusal, which lands in a
        # transcript where the logging filter does not apply. Doing it here
        # means every future branch that interpolates `detail` is safe by
        # default rather than safe if someone remembered.
        from .redact import scrub

        detail = scrub(detail)
        super().__init__(detail)
        self.kind = kind
        self.upstream = upstream
        self.detail = detail
        self.aadsts = aadsts
        self.correlation_id = correlation_id

    @property
    def operator_fault(self) -> bool:
        return self.kind in _OPERATOR_FAULT

    @property
    def transient(self) -> bool:
        return self.kind in ("entra_unreachable", "unknown")

    def __repr__(self) -> str:  # never interpolate a token into a repr
        return (
            f"OBOError(kind={self.kind!r}, upstream={self.upstream!r}, "
            f"aadsts={self.aadsts!r})"
        )


@dataclass(slots=True)
class _Entry:
    """One cache slot. `task` is the exchange itself, shared by every waiter."""

    task: asyncio.Task[str]
    expires_at: float  # time.monotonic()

    def __repr__(self) -> str:
        # MUST NOT delegate to the Task's own repr: a finished asyncio.Task
        # renders as "<Task finished ... result='eyJ...'>", which prints the
        # exchanged bearer token. A stray debug log or a traceback rendering
        # this cache would leak a live credential into somewhere durable, and a
        # leaked token nobody notices is never rotated. Found by
        # tests/test_obo_cache.py, which now pins it.
        state = "pending"
        if self.task.done():
            state = "failed" if self.task.exception() is not None else "ready"
        return f"_Entry(state={state}, expires_at={self.expires_at:.0f})"


class OBOExchanger:
    """Per-(user, upstream) tokens with a single-flight, bounded cache.

    Cache key is (sha256(inbound token), scope). Hashing is not for secrecy --
    the token is in memory anyway -- it is so no log line, repr or traceback can
    print a bearer token by accident. It also fixes the key size, and it makes
    re-authentication self-busting: a new inbound token is a different key, so a
    user who re-consents after a Conditional Access prompt is never served a
    stale refusal.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        *,
        http: httpx.AsyncClient | None = None,
        max_entries: int = 512,
        timeout: float = 10.0,
    ) -> None:
        self._token_url = (
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        )
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = http or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=5.0),
            headers={"User-Agent": "mcp-gateway"},
        )
        self._entries: OrderedDict[tuple[str, str], _Entry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._max_entries = max_entries
        self.exchanges = 0  # observability; asserted by tests/test_obo_cache.py

    async def aclose(self) -> None:
        await self._http.aclose()

    def __repr__(self) -> str:
        return f"OBOExchanger(entries={len(self._entries)}, exchanges={self.exchanges})"

    async def token_for(self, inbound_token: str, scope: str, *, upstream: str) -> str:
        """The upstream-audience token for this caller. Raises OBOError."""
        key = (hashlib.sha256(inbound_token.encode("utf-8")).hexdigest(), scope)
        now = time.monotonic()

        async with self._lock:
            self._purge(now)
            entry = self._entries.get(key)
            if entry is not None and entry.expires_at > now:
                self._entries.move_to_end(key)
                task = entry.task
            else:
                self._entries.pop(key, None)
                task = asyncio.ensure_future(
                    self._exchange(inbound_token, scope, upstream, key)
                )
                self._entries[key] = _Entry(
                    task=task, expires_at=now + _PROVISIONAL_TTL_S
                )
                self._evict()

        # shield: if THIS caller is cancelled -- client hung up, tool timed out,
        # one branch of a gather losing a race -- the shared exchange must
        # survive for everyone else awaiting it. A bare `await task` would
        # cancel the task and turn one caller's timeout into every caller's
        # failure.
        return await asyncio.shield(task)

    def _purge(self, now: float) -> None:
        """Drop expired slots. Never drop a running exchange: a slow Entra must
        not cause a second, duplicate exchange."""
        stale = [
            k for k, e in self._entries.items() if e.expires_at <= now and e.task.done()
        ]
        for k in stale:
            self._entries.pop(k, None)

    def _evict(self) -> None:
        """Bound the cache, oldest first, but only ever evict FINISHED slots.
        Evicting an in-flight task raises CancelledError in the callers
        shielding it, so an overshoot is preferred -- and logged, because it
        means max_entries is wrong for the concurrency we actually have."""
        while len(self._entries) > self._max_entries:
            victim = next((k for k, e in self._entries.items() if e.task.done()), None)
            if victim is None:
                logger.warning(
                    "OBO cache over budget with %d in-flight exchanges "
                    "(max_entries=%d); raise ENTRA_OBO_CACHE_MAX",
                    len(self._entries),
                    self._max_entries,
                )
                return
            self._entries.pop(victim, None)

    def _set_expiry(self, key: tuple[str, str], ttl: float) -> None:
        """Lock-free on purpose: only the owning task writes its own slot's
        expiry, and token_for() reads it under the lock. If the slot has already
        been replaced this writes to an orphan, which is harmless."""
        entry = self._entries.get(key)
        if entry is not None:
            entry.expires_at = time.monotonic() + ttl

    async def _exchange(
        self, assertion: str, scope: str, upstream: str, key: tuple[str, str]
    ) -> str:
        form = {
            "grant_type": GRANT_TYPE,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "assertion": assertion,
            "scope": scope,
            # No offline_access. A refresh token for the upstream would make
            # this container a credential store needing encryption at rest.
            # Instead, when the inbound token rolls over the new hash simply
            # misses the cache and we exchange again.
            "requested_token_use": "on_behalf_of",
        }
        started = time.monotonic()
        self.exchanges += 1
        try:
            resp = await self._http.post(self._token_url, data=form)
        except httpx.HTTPError as exc:
            # Per-item degradation: this upstream is unusable, the others may be
            # fine. Never treated as "no tools", always as a loud failure.
            self._set_expiry(key, _NEGATIVE_TTL_S)
            raise OBOError(
                "entra_unreachable",
                upstream,
                f"could not reach Entra to exchange your sign-in "
                f"({type(exc).__name__})",
            ) from exc

        if resp.status_code != 200:
            err = self._classify(resp, upstream)
            self._set_expiry(key, _NEGATIVE_TTL_S)
            log = logger.error if err.operator_fault else logger.warning
            log(
                "OBO DENIED upstream=%s kind=%s aadsts=%s corr=%s key=%s%s",
                upstream,
                err.kind,
                err.aadsts,
                err.correlation_id,
                key[0][:8],
                " GATEWAY MISCONFIG" if err.operator_fault else "",
            )
            raise err

        try:
            body = resp.json()
        except ValueError as exc:
            self._set_expiry(key, _NEGATIVE_TTL_S)
            raise OBOError(
                "unknown", upstream, "Entra returned 200 with an unreadable body"
            ) from exc

        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            self._set_expiry(key, _NEGATIVE_TTL_S)
            raise OBOError(
                "unknown",
                upstream,
                "Entra returned 200 with no access_token; refusing to continue "
                "rather than calling the upstream unauthenticated",
            )

        ttl = max(float(body.get("expires_in") or 0.0) - _EXPIRY_MARGIN_S, _MIN_TTL_S)
        self._set_expiry(key, ttl)
        logger.info(
            "OBO ok upstream=%s ttl=%.0fs elapsed=%dms key=%s",
            upstream,
            ttl,
            int((time.monotonic() - started) * 1000),
            key[0][:8],
        )
        return token  # never logged, never stored anywhere but this Task

    def _classify(self, resp: httpx.Response, upstream: str) -> OBOError:
        try:
            body = resp.json()
        except ValueError:
            body = {}
        error = str(body.get("error") or "")
        desc = str(body.get("error_description") or "")
        suberror = str(body.get("suberror") or "")
        corr = str(body.get("correlation_id") or "") or resp.headers.get(
            "client-request-id", ""
        )
        match = _AADSTS_RE.search(desc)
        code = match.group(1) if match else None

        # The top-level OAuth error is more reliable than the AADSTS number, so
        # it wins. interaction_required means a human must complete something
        # (MFA, terms of use, device compliance): there is no server-side fix,
        # and MCP has no channel to relay a claims challenge mid-call.
        if error == "interaction_required" or suberror in (
            "basic_action",
            "consent_required",
            "message_only",
        ):
            kind = "step_up"
        else:
            kind = _KIND_BY_CODE.get(code or "", "unknown")

        return OBOError(
            kind,
            upstream,
            desc or error or f"HTTP {resp.status_code}",
            aadsts=(f"AADSTS{code}" if code else None),
            correlation_id=corr or None,
        )
