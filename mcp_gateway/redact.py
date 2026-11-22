"""Keep credentials out of logs.

An MCP result and a container log both land somewhere durable, so a leaked
bearer token is leaked permanently and nobody thinks to rotate it. This gateway
handles more credential material than any server behind it: the
caller's inbound token, one exchanged token per upstream, and its own client
secret.

Allowlist thinking does not fit a log FILTER, which sees arbitrary text, so this
is a targeted scrubber over the shapes that actually occur here, and it is
backed by tests/test_redaction.py rather than by confidence. The real defense is
upstream of this: never interpolate a token into a message in the first place.
Nothing in this package logs a token, and the OBO cache is keyed on a hash
precisely so a stray repr cannot print one.
"""

from __future__ import annotations

import logging
import re

REDACTED = "<redacted>"

# A JWT: three base64url segments. Entra access tokens and the inbound
# assertion both match. Minimum lengths keep this off ordinary dotted words.
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

# Form-encoded or key=value credential material, as it would appear if anyone
# ever logged the OBO request body.
_FORM = re.compile(
    r"(?i)\b(client_secret|assertion|access_token|refresh_token|id_token|password)"
    r"(\s*[=:]\s*)([^\s&\"',}]+)"
)

# "Authorization: Bearer xxx" in any casing, including inside a repr of a header
# list, where the JWT pattern would not fire for an opaque token.
_BEARER = re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{12,})")


def scrub(text: str) -> str:
    """Remove credential-shaped substrings. Safe to call on anything."""
    text = _JWT.sub(REDACTED, text)
    text = _FORM.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    return text


class RedactingFilter(logging.Filter):
    """Scrub every log record on its way out.

    Rewrites `msg` and `args` rather than the formatted line, so the scrub
    survives handlers that format independently. A filter that raised would
    silence the log entirely, which is worse than a missed redaction, so
    failures fall through to the original record and say so.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = scrub(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = {k: _scrub_value(v) for k, v in record.args.items()}
                else:
                    record.args = tuple(_scrub_value(a) for a in record.args)
        except Exception:  # noqa: BLE001 - a logging filter must never raise
            # Swallowed deliberately: raising here would drop the log line, and
            # losing the record is worse than an unscrubbed one. Nothing in this
            # package logs a token, so this path should be unreachable.
            logging.getLogger("mcp_gateway.redact").debug(
                "redaction failed for a record", exc_info=True
            )
        return True


def _scrub_value(value: object) -> object:
    return scrub(value) if isinstance(value, str) else value


def install(level: str = "INFO") -> None:
    """Configure logging for the process, with redaction on every handler."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )
    filt = RedactingFilter()
    root = logging.getLogger()
    for handler in root.handlers:
        handler.addFilter(filt)
    # Also on the root logger itself, so records created before a handler is
    # attached still pass through it.
    root.addFilter(filt)
