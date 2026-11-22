"""Prefix once, and refuse to serve a collision.

The collision case is not cosmetic. fastmcp's AggregateProvider only WARNS on a
duplicate component key and returns both entries; its own source comment says an
errorable mode was rejected because cross-provider collisions happen at runtime
and would crash list calls in production. The wire handler then dedupes by name
and the call path resolves by version sort, which is arbitrary among unversioned
tools. Two per-customer servers built from one template share every bare tool
name, so an arbitrary route between them is a disclosure. Since the library will
not stop it, this check must.
"""

from __future__ import annotations

import pytest

from mcp_gateway.config import ConfigError, _validate_namespace
from mcp_gateway.naming import CollisionError, assert_no_collisions, namespace_of, public_name

# The shape of the real problem: two phone-system servers, one per customer,
# built from the same template, so their bare tool names are identical.
SHARED_PHONE_TOOLS = [
    "capabilities",
    "get_recording_link",
    "list_answer_rules",
    "list_call_queues",
    "list_cdrs",
    "list_devices",
    "list_domains",
    "list_phone_numbers",
    "list_registrations",
    "list_time_frames",
    "list_users",
]


def test_bare_names_get_prefixed():
    assert public_name("inventory", "list_hosts") == "inventory_list_hosts"
    assert public_name("helpdesk", "get_summary") == "helpdesk_get_summary"


def test_already_prefixed_names_are_left_alone():
    """Otherwise every self-prefixing server pays for docs_docs_capabilities in
    every tool list, on every turn."""
    assert public_name("docs", "docs_capabilities") == "docs_capabilities"
    assert public_name("mail", "mail_get_forwarding") == "mail_get_forwarding"


def test_namespace_lookup_is_exact_not_prefix_matching():
    known = frozenset({"inventory", "docs", "helpdesk"})
    assert namespace_of("inventory_list_hosts", known) == "inventory"
    assert namespace_of("docs_capabilities", known) == "docs"
    # A local gateway tool belongs to no namespace.
    assert namespace_of("gw_status", known) is None
    # A namespace-like head that is not configured must not be claimed.
    assert namespace_of("phonea_list_devices", known) is None
    # No separator at all.
    assert namespace_of("capabilities", known) is None


def test_namespaces_may_not_contain_underscores():
    """The first underscore is the separator, so an underscore in a namespace
    would make policy routing ambiguous."""
    _validate_namespace("inventory", "test")
    with pytest.raises(ConfigError):
        _validate_namespace("help_desk", "test")
    with pytest.raises(ConfigError):
        _validate_namespace("Inventory", "test")


def test_distinct_namespaces_do_not_collide():
    assert_no_collisions(
        {
            "inventory": ["list_hosts", "capabilities"],
            "docs": ["docs_capabilities", "docs_search"],
            "helpdesk": ["get_summary", "agent_workload"],
        }
    )


def test_namespacing_separates_two_customers_with_identical_tool_names():
    """What an UN-namespaced gateway would route arbitrarily between two
    customers' phone systems. Namespaced, they coexist safely. This is the test
    that says why namespacing is mandatory rather than a nicety."""
    assert_no_collisions({"phonea": SHARED_PHONE_TOOLS, "phoneb": SHARED_PHONE_TOOLS})

    public_a = {public_name("phonea", n) for n in SHARED_PHONE_TOOLS}
    public_b = {public_name("phoneb", n) for n in SHARED_PHONE_TOOLS}
    assert not (public_a & public_b), "namespacing failed to separate them"


def test_prefix_once_can_collapse_two_tools_onto_one_name():
    """The hazard prefix-once itself introduces, and the reason this check
    exists at all. A server exposing BOTH `capabilities` and
    `docs_capabilities` collapses them onto one public name."""
    with pytest.raises(CollisionError) as exc:
        assert_no_collisions({"docs": ["capabilities", "docs_capabilities"]})
    message = str(exc.value)
    assert "docs_capabilities" in message
    # Both sources must be named, or the operator cannot tell what to rename.
    assert "docs:capabilities" in message
    assert "docs:docs_capabilities" in message


def test_cross_namespace_collisions_are_structurally_impossible():
    """Prefix-once skips only its OWN namespace's prefix, so an inventory tool
    that happens to be called `docs_capabilities` still comes out as
    `inventory_docs_capabilities`. Ugly, and unambiguous.

    If a future change ever makes prefix-once skip ANY known prefix, this test
    fails and the cross-customer routing risk is back."""
    assert_no_collisions({"docs": ["docs_capabilities"], "inventory": ["docs_capabilities"]})
    assert public_name("inventory", "docs_capabilities") == "inventory_docs_capabilities"
    assert public_name("docs", "docs_capabilities") == "docs_capabilities"


def test_every_clash_is_reported_not_just_the_first():
    """An operator fixing these one redeploy at a time is an afternoon lost."""
    with pytest.raises(CollisionError) as exc:
        assert_no_collisions(
            {"helpdesk": ["capabilities", "helpdesk_capabilities", "summary", "helpdesk_summary"]}
        )
    message = str(exc.value)
    assert "helpdesk_capabilities" in message
    assert "helpdesk_summary" in message
    assert message.startswith("2 tool name collision(s)")
