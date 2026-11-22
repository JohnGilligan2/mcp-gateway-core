"""Shared test plumbing.

Stub upstreams come from scripts/stub_fleet.py: real MCP servers over real HTTP
on 127.0.0.1, because the bugs this suite exists to catch live in the wire
layer. No test reaches beyond the loopback interface.

`async def` tests run under asyncio.run() via the hook below, so the suite needs
pytest and nothing else (no pytest-asyncio or anyio plugin).
"""

from __future__ import annotations

import asyncio
import inspect
import os

import pytest

from scripts.stub_fleet import free_port, make_upstream, serve  # noqa: F401 (re-exported)

os.environ.setdefault("PYTHONUTF8", "1")


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        names = pyfuncitem._fixtureinfo.argnames
        kwargs = {name: pyfuncitem.funcargs[name] for name in names}
        asyncio.run(pyfuncitem.obj(**kwargs))
        return True
    return None
