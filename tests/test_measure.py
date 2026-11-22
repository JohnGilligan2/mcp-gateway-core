"""The context-cost benchmark, run against the made-up fleet as loopback stubs.

Run with `-s` to see the table:

    python -m pytest tests/test_measure.py -s

The assertions are about the SHAPE of the result, not the magnitude:
aggregating flat must not be reported as a saving, and search must actually
shrink what the client is handed. Magnitudes depend on the real servers' tool
descriptions, which is why the script can be pointed at real servers.
"""

from __future__ import annotations

import asyncio
import io

from scripts.measure_schema_tokens import (
    Scenario,
    measure_fleet_file,
    report,
    schema_tokens,
)
from scripts.stub_fleet import DEFAULT_FLEET, load_fleet


async def test_three_scenarios_on_the_example_fleet():
    direct, flat, search = await measure_fleet_file(DEFAULT_FLEET)
    report([direct, flat, search])

    # Every upstream tool is present in the flat view (each stub also carries
    # echo_headers), plus the gateway's own gw_status.
    servers = load_fleet(DEFAULT_FLEET)
    upstream_tools = sum(len(s["tools"]) + 1 for s in servers)
    assert direct.tools == upstream_tools
    assert flat.tools == upstream_tools + 1

    # Flat aggregation is NOT a saving. Namespacing lengthens names and the
    # gateway adds tools of its own. If this ever inverts, the docstring in
    # scripts/measure_schema_tokens.py explaining why is wrong and should be
    # rewritten rather than the assertion deleted.
    assert flat.tokens >= direct.tokens, (
        "flat aggregation appeared cheaper than direct, which contradicts the "
        "premise this design is built on"
    )

    # Search is the part that actually pays. It must be a large cut, not a
    # rounding difference.
    assert search.tokens < direct.tokens / 2, (search.tokens, direct.tokens)
    assert search.tools < 10, "search should collapse the catalog, not list it"


def test_server_side_tools_are_measured_with_their_schema():
    """The bug the _input_schema normalization exists for: a server-side
    fastmcp Tool carries `parameters`, not `inputSchema`. Reading only
    `inputSchema` scored every server-side tool as schema-free and made flat
    aggregation look cheaper than direct."""
    from fastmcp import FastMCP

    mcp = FastMCP(name="t")

    @mcp.tool(name="lookup", description="Look something up.")
    async def lookup(query: str, limit: int = 10) -> str:
        return query

    tools = asyncio.run(mcp.list_tools())
    _, with_schema, _ = schema_tokens(tools)
    no_schema = type("T", (), {"name": "lookup", "description": "Look something up."})()
    _, without, _ = schema_tokens([no_schema])
    assert with_schema > without + 40, "the input schema was not counted"


def test_the_report_prints_all_three_rows():
    rows = [
        Scenario("direct", 34, 8000, 2000),
        Scenario("gateway, flat", 35, 8400, 2100),
        Scenario("gateway, tool search", 3, 1000, 250),
    ]
    text = report(rows, out=io.StringIO())
    assert "+5%" in text and "-88%" in text and "baseline" in text
