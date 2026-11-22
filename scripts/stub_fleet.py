"""Stub upstream MCP servers over real HTTP on the loopback interface.

Used by the tests, the benchmark and the example. Everything runs the actual
transport rather than an in-process shortcut, because the bugs worth catching
in a gateway live in the wire layer: duplicate authorization headers, header
forwarding flags, connection failure handling. An in-memory client would not
see any of them. Nothing here leaves 127.0.0.1.
"""

from __future__ import annotations

import contextlib
import json
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import uvicorn
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_request
from fastmcp.tools.base import Tool

REPO = Path(__file__).resolve().parents[1]
DEFAULT_FLEET = REPO / "fleet.example.json"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class RunningServer:
    """A uvicorn server on a background thread, with a hard stop."""

    def __init__(self, app, port: int) -> None:
        self.port = port
        self.url = f"http://127.0.0.1:{port}/mcp"
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self) -> None:
        self._thread.start()
        for _ in range(200):
            if self._server.started:
                return
            threading.Event().wait(0.05)
        raise RuntimeError(f"server on {self.port} did not start")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


@contextlib.contextmanager
def serve(mcp: FastMCP) -> Iterator[RunningServer]:
    port = free_port()
    server = RunningServer(mcp.http_app(path="/mcp", stateless_http=True), port)
    server.start()
    try:
        yield server
    finally:
        server.stop()


def make_upstream(name: str, tools: dict[str, str]) -> FastMCP:
    """An upstream with the given zero-argument tools, plus `echo_headers`.

    `echo_headers` returns the RAW headers the upstream received. Raw, not
    get_http_headers(): a lowercased dict view COLLAPSES a mixed-case
    duplicate, which is precisely how the two-authorization-headers bug
    escapes review. The test must see what went on the wire.

    Each other tool returns "<server>:<tool>", so a test can tell which
    upstream a call was routed to.
    """
    mcp: FastMCP = FastMCP(name=name)

    @mcp.tool(name="echo_headers", description=f"Return raw headers seen by {name}.")
    async def echo_headers() -> dict:
        request = get_http_request()
        return {
            "server": name,
            "headers": [
                [k.decode("latin-1"), v.decode("latin-1")]
                for k, v in request.scope.get("headers", [])
            ],
        }

    for tool_name, description in tools.items():

        def _make(tn: str, srv: str):
            async def _tool() -> str:
                return f"{srv}:{tn}"

            return _tool

        mcp.add_tool(
            Tool.from_function(fn=_make(tool_name, name), name=tool_name, description=description)
        )
    return mcp


def load_fleet(path: str | Path = DEFAULT_FLEET) -> list[dict]:
    """The `servers` list from a fleet file: namespace, name, group, tools."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    servers = data["servers"]
    for s in servers:
        for key in ("namespace", "name", "tools"):
            if key not in s:
                raise ValueError(f"fleet entry missing {key!r}: {s}")
    return servers


@contextlib.contextmanager
def serve_fleet(servers: list[dict]) -> Iterator[dict[str, RunningServer]]:
    """Start one stub per fleet entry. Yields namespace -> RunningServer."""
    with contextlib.ExitStack() as stack:
        running = {
            s["namespace"]: stack.enter_context(serve(make_upstream(s["namespace"], s["tools"])))
            for s in servers
        }
        yield running
