"""Small helpers shared by the test modules."""

from __future__ import annotations

from mcp_gateway.config import UpstreamConfig


def cfg_for(ns: str, url: str, **overrides) -> UpstreamConfig:
    """An upstream config pointing at a loopback stub, named under example.com."""
    host = f"{ns}-mcp.example.com"
    values = dict(
        name=f"{ns}-mcp",
        namespace=ns,
        url=url,
        identifier_uri=f"https://{host}/mcp",
        host_header=host,
        scope=f"https://{host}/mcp/.default",
        init_timeout=5.0,
        call_timeout=10.0,
    )
    values.update(overrides)
    return UpstreamConfig(**values)


class StubExchanger:
    """Stands in for OBOExchanger. Records what it was asked to exchange."""

    def __init__(self, token: str = "upstream-token") -> None:
        self.token = token
        self.calls: list[tuple[str, str, str]] = []

    async def token_for(self, inbound_token: str, scope: str, *, upstream: str) -> str:
        self.calls.append((inbound_token, scope, upstream))
        return self.token
