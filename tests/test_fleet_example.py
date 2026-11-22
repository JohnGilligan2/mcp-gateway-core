"""The example fleet file is well formed and would boot without a collision."""

from __future__ import annotations

from mcp_gateway.config import _validate_namespace
from mcp_gateway.naming import assert_no_collisions
from scripts.stub_fleet import DEFAULT_FLEET, load_fleet


def test_example_fleet_loads_and_namespaces_are_valid():
    servers = load_fleet(DEFAULT_FLEET)
    assert len(servers) >= 2
    for s in servers:
        _validate_namespace(s["namespace"], "fleet.example.json")
        assert s["tools"], f"{s['namespace']} has no tools"
        assert all(desc.strip() for desc in s["tools"].values())


def test_example_fleet_has_no_collisions_after_namespacing():
    servers = load_fleet(DEFAULT_FLEET)
    assert_no_collisions({s["namespace"]: list(s["tools"]) for s in servers})
