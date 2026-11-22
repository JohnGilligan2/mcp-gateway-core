"""Execution-level boot test. Unit-green is not deploy-green.

Launches `python -m mcp_gateway` as a SUBPROCESS, exactly as a container would,
and probes it over real HTTP on 127.0.0.1 from outside the process.
Monkeypatching FastMCP.run only proves the arguments were assembled; it never
executes the serving path where import errors, wiring mistakes and startup
ordering actually bite.

The subprocess's captured output is the failure detail on every assertion. That
is what turns "it hung" into a diagnosis. Nothing here contacts the identity
provider: the server only validates tokens, and no token is presented.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from scripts.stub_fleet import free_port

REPO = Path(__file__).resolve().parents[1]

TENANT = "example-tenant"
CLIENT = "example-gateway-client"
HOST = "mcp-gateway.example.com"


def pinned_fastmcp() -> str:
    text = (REPO / "requirements.txt").read_text(encoding="utf-8")
    match = re.search(r"^fastmcp==(\S+)", text, re.MULTILINE)
    assert match, "requirements.txt must pin fastmcp exactly"
    return match.group(1)


def base_env(port: int, **overrides: str) -> dict[str, str]:
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "PYTHONPATH": str(REPO),
        "MCP_TRANSPORT": "http",
        "MCP_HOST": "127.0.0.1",
        "MCP_PORT": str(port),
        "MCP_PATH": "/mcp",
        "MCP_AUTH_ENABLED": "true",
        "MCP_BASE_URL": f"https://{HOST}",
        "MCP_PUBLIC_URL": f"https://{HOST}",
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT,
        "ENTRA_IDENTIFIER_URI": f"https://{HOST}/mcp",
        "ENTRA_SCOPE_NAME": "access_as_user",
        "ENTRA_ADVERTISE_OFFLINE_ACCESS": "true",
        "ENTRA_GATEWAY_CLIENT_SECRET": "not-a-real-secret",
        "GATEWAY_UPSTREAMS": "inventory,docs,helpdesk",
        # Nothing is listening on these. The gateway must still come up: an
        # upstream being down is not a reason to refuse to serve.
        "GW_UP_INVENTORY_URL": "http://127.0.0.1:1/mcp",
        "GW_UP_INVENTORY_IDENTIFIER_URI": "https://inventory-mcp.example.com/mcp",
        "GW_UP_DOCS_URL": "http://127.0.0.1:1/mcp",
        "GW_UP_DOCS_IDENTIFIER_URI": "https://docs-mcp.example.com/mcp",
        "GW_UP_HELPDESK_URL": "http://127.0.0.1:1/mcp",
        "GW_UP_HELPDESK_IDENTIFIER_URI": "https://helpdesk-mcp.example.com/mcp",
        "GW_UP_INVENTORY_INIT_TIMEOUT": "2",
        "GW_UP_DOCS_INIT_TIMEOUT": "2",
        "GW_UP_HELPDESK_INIT_TIMEOUT": "2",
    }
    env.update(overrides)
    return env


class Boot:
    def __init__(self, env: dict[str, str], port: int) -> None:
        self.port = port
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway"],
            cwd=str(REPO),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def wait_for_health(self, timeout: float = 60.0) -> httpx.Response:
        deadline = time.monotonic() + timeout
        last: Exception | None = None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(
                    f"process exited with {self.proc.returncode} before serving.\n"
                    f"--- output ---\n{self.output()}"
                )
            try:
                r = httpx.get(f"http://127.0.0.1:{self.port}/healthz", timeout=2.0)
                if r.status_code == 200:
                    return r
            except httpx.HTTPError as exc:  # retried until the deadline
                last = exc
            time.sleep(0.25)
        raise AssertionError(
            f"never served /healthz within {timeout}s (last error: {last}).\n"
            f"--- output ---\n{self.output()}"
        )

    def output(self) -> str:
        try:
            self.proc.kill()
            out, _ = self.proc.communicate(timeout=10)
            return out or ""
        except (OSError, subprocess.SubprocessError, ValueError):
            # Swallowed: this runs only to decorate a failure message that is
            # already being raised; losing the output must not mask the failure.
            return "(could not read process output)"

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.communicate(timeout=10)
        except (OSError, subprocess.SubprocessError, ValueError):
            # Swallowed: teardown of an already-dead child; nothing to report.
            pass


def test_the_server_boots_and_serves_the_real_endpoints():
    port = free_port()
    boot = Boot(base_env(port), port)
    try:
        body = boot.wait_for_health().json()

        assert body["status"] == "ok"
        assert body["service"] == "mcp-gateway"
        # Image drift is visible from outside the container.
        assert body["fastmcp"] == pinned_fastmcp(), body
        assert body["auth_enabled"] is True
        assert body["obo_enabled"] is True
        assert body["upstreams"] == 3
        assert sorted(body["namespaces"]) == ["docs", "helpdesk", "inventory"]

        # The discovery document is what the MCP client reads before it ever
        # calls /mcp.
        prm = httpx.get(
            f"http://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp", timeout=5.0
        )
        assert prm.status_code == 200, prm.text
        doc = prm.json()
        assert doc["resource"].rstrip("/").endswith("/mcp"), doc
        # FULL-URL scope, not the bare name. Advertising `access_as_user` alone
        # is what produces AADSTS70011 at sign-in.
        scopes = doc.get("scopes_supported", [])
        assert f"https://{HOST}/mcp/access_as_user" in scopes, scopes
        # Without this the connector gets no refresh token and dies quietly at
        # token expiry.
        assert "offline_access" in scopes, scopes
        assert any(TENANT in str(a) for a in doc.get("authorization_servers", [])), doc

        # Unauthenticated calls are refused, with the pointer a client needs.
        unauth = httpx.post(
            f"http://127.0.0.1:{port}/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
            timeout=5.0,
        )
        assert unauth.status_code == 401, unauth.text
        assert "WWW-Authenticate" in unauth.headers
    finally:
        boot.stop()


def refused(env: dict[str, str], port: int) -> str:
    boot = Boot(env, port)
    try:
        out, _ = boot.proc.communicate(timeout=60)
        assert boot.proc.returncode != 0, out
        return out
    finally:
        boot.stop()


def test_it_refuses_to_start_without_the_client_secret():
    """A gateway that validates a user but cannot obtain an upstream token fails
    every tool call, which is indistinguishable from every upstream being down.
    Refuse loudly at boot instead."""
    port = free_port()
    env = base_env(port)
    env.pop("ENTRA_GATEWAY_CLIENT_SECRET")
    assert "ENTRA_GATEWAY_CLIENT_SECRET" in refused(env, port)


def test_it_refuses_a_secret_containing_a_dollar_sign():
    """Compose expands variables in values it substitutes, so a '$' in a secret
    arrives with its middle deleted. Refuse it at boot."""
    port = free_port()
    out = refused(base_env(port, ENTRA_GATEWAY_CLIENT_SECRET="abc$def"), port)
    assert "$" in out and "Compose" in out, out


def test_it_refuses_an_identifier_uri_that_is_not_the_mcp_url():
    """The Application ID URI, the advertised scope and the token audience must
    all name the same /mcp URL (AADSTS9010010 otherwise)."""
    port = free_port()
    out = refused(base_env(port, ENTRA_IDENTIFIER_URI=f"api://{CLIENT}"), port)
    assert "identifier URI" in out, out


@pytest.mark.parametrize("namespace", ["help_desk", "help-desk", "help.desk"])
def test_it_refuses_an_invalid_namespace(namespace: str):
    """The first underscore in a tool name is the namespace separator, so a
    namespace containing one would make policy routing ambiguous. Case is not
    an error: config lowercases the list deliberately."""
    port = free_port()
    env = base_env(port, GATEWAY_UPSTREAMS=namespace)
    env[f"GW_UP_{namespace.upper()}_URL"] = "http://127.0.0.1:1/mcp"
    env[f"GW_UP_{namespace.upper()}_IDENTIFIER_URI"] = "https://x.example.com/mcp"
    assert "namespace" in refused(env, port).lower()
