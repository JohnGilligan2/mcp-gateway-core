"""Nothing credential-shaped may reach a log line or a tool result.

A gateway handles more credential material than any server behind it: the
caller's inbound token, one exchanged token per upstream, and its own client
secret. An MCP result and a container log both land somewhere durable, so a
leaked bearer token is leaked permanently and nobody thinks to rotate it.
"""

from __future__ import annotations

import logging

from mcp_gateway.obo import OBOError
from mcp_gateway.redact import RedactingFilter, scrub
from mcp_gateway.upstreams import user_message
from tests.util import cfg_for

# A JWT-shaped string with a made-up payload. Not a real token.
JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJhdWQiOiJodHRwczovL2V4YW1wbGUifQ"
    ".c2lnbmF0dXJlLWhlcmUtbm90LXJlYWw"
)


def test_a_jwt_is_scrubbed():
    assert JWT not in scrub(f"token={JWT} rest")
    assert "<redacted>" in scrub(f"token={JWT} rest")


def test_form_credentials_are_scrubbed():
    body = f"grant_type=jwt-bearer&client_secret=s3cr3t-value&assertion={JWT}"
    out = scrub(body)
    assert "s3cr3t-value" not in out
    assert JWT not in out
    # The key names survive, so a log still says WHAT was withheld.
    assert "client_secret" in out
    assert "assertion" in out


def test_opaque_bearer_tokens_are_scrubbed_even_without_jwt_shape():
    """An access token is not always a readable JWT, and a header repr would
    otherwise print it verbatim."""
    out = scrub("headers=[('authorization', 'Bearer AbCdEf0123456789xyz')]")
    assert "AbCdEf0123456789xyz" not in out
    assert "Bearer <redacted>" in out


def test_ordinary_text_is_left_alone():
    """A scrubber that mangles normal logs gets turned off, so it must not."""
    for text in [
        "upstream inventory-mcp unavailable: ConnectError",
        "tools/list user=riley entitled=['inventory']",
        "OBO ok upstream=docs-mcp ttl=3480s elapsed=210ms key=9f2a1c4b",
    ]:
        assert scrub(text) == text


def test_the_logging_filter_rewrites_message_and_args(caplog):
    logger = logging.getLogger("mcp_gateway.test_redaction")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO):
        logger.info("exchanged %s for %s", JWT, "Bearer AbCdEf0123456789xyz")
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert JWT not in blob
    assert "AbCdEf0123456789xyz" not in blob


def test_user_facing_refusals_carry_no_credential_material():
    """Every branch of the refusal text is checked, because these strings are
    the ones that reach a transcript."""
    up = cfg_for("inventory", "http://127.0.0.1:8101/mcp")
    for kind in [
        "step_up",
        "not_consented",
        "not_assigned",
        "bad_scope",
        "bad_secret",
        "bad_assertion",
        "entra_unreachable",
        "unknown",
    ]:
        exc = OBOError(
            kind,
            up.name,
            # A hostile-but-plausible detail: the identity provider echoing the
            # assertion back.
            f"AADSTS500131: assertion {JWT} failed validation",
            aadsts="AADSTS500131",
            correlation_id="abc-123",
        )
        message = user_message(up, exc)
        # NOT scrub(message). This string goes straight to the client as a tool
        # error and lands in a transcript, where the logging filter never runs.
        # It has to be clean as constructed. Asserting on the scrubbed copy
        # would pass while the real leak shipped -- which is exactly what this
        # test did before OBOError started scrubbing at construction.
        assert JWT not in message
        assert "<redacted>" in message or kind != "unknown"
        # Every refusal must say the request did not reach the server, so a
        # user never has to guess whether something half-happened.
        assert "Nothing was read" in message


def test_the_error_repr_does_not_carry_the_detail_string():
    """A traceback renders repr(), and the detail can contain an echoed
    assertion."""
    exc = OBOError("bad_assertion", "inventory-mcp", f"assertion {JWT} rejected")
    assert JWT not in repr(exc)
