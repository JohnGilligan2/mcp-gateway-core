# mcp-gateway-core

One MCP endpoint in front of a fleet of MCP servers. You sign in once. You see only the tools your groups allow, and the model gets a search tool instead of every schema in the fleet.

This is the core of a gateway I built and run in front of the MCP servers at an MSP, pulled out on its own with the deployment stripped away and a made-up fleet in place of the real one.

## The problem

I had about twenty MCP servers in production, each one its own connector with its own sign-in. Somebody who needed several of them signed in to each one separately. Every connected server also sends its full tool list into the model's context on every turn, whether a tool gets called or not.

The obvious fix is a gateway that merges them. I measured that before building it, and merging on its own makes the context problem a little worse. Namespacing makes every tool name longer and the gateway adds a tool of its own, so the merged catalog costs more than connecting the servers directly. What pays is filtering: give the model a search tool and let it pull the few schemas it needs for the task in front of it.

## The number

Estimated tokens of tool schema sent on every turn, measured against stub servers sized like the first three real servers the gateway fronted. The stubs had 12, 11 and 8 tools, plus one header-echo test tool each.

| | tools | est. tokens | vs direct |
|---|---:|---:|---:|
| each server connected directly | 34 | 1,990 | baseline |
| gateway, flat aggregation | 35 | 2,065 | +4% |
| gateway, tool search | 3 | 252 | -87% |

So tool search is on by default, and flat mode exists only to measure against. The estimate is bytes / 4 over each tool's name, description and input schema.

The benchmark is in this repo and reruns on a made-up fleet of the same shape (`fleet.example.json`). On that fleet it prints 2,053, then 2,147 (+5%), then 252 (-88%). The descriptions are different, so the first two numbers move a little. The search number doesn't move. Search sends the same three small tools however big the fleet gets.

## What it's careful about

The caller's token never goes upstream. Claude presents a token whose audience is the gateway. For each upstream call the gateway does an Entra On-Behalf-Of exchange for a token scoped to that one server. Each server's own app assignment still decides who gets in, and the gateway never holds an app-only credential. The exchange is cached per user and per server and is single-flight, so twenty concurrent calls from one person to one server cost one round trip to Entra.

`tests/test_no_token_passthrough.py` reads the raw headers the upstream received and fails if the caller's token is among them. It also carries a negative control that reproduces the leak you get from passing the exchanged token through `headers=` with header forwarding on.

Every tool is prefixed with its server's namespace, once. A server that already prefixes its own tools keeps its names (`docs_search` stays `docs_search`). In the original fleet, two customers' phone servers built from one template shared eleven bare tool names. fastmcp (3.4.5) only warns on a duplicate and then routes the call to one of them more or less at random, which across two customers is a data leak. So the gateway refuses to serve a catalog with a duplicate name in it.

A person sees only the namespaces their app roles grant. That's enforced when tools are listed and again when one is called. Search is filtered too. There are two independent layers, and either one alone keeps search clean. A test removes both and shows other namespaces' tools leaking into search results.

If an upstream is down, its tools are replaced by one visible `<namespace>_unavailable` tool that says why. Everything else keeps working.

## Run it

```
pip install -r requirements-dev.txt
python -m pytest
python example/demo.py
python scripts/measure_schema_tokens.py
```

The 63 tests take about four and a half minutes because they start real MCP servers over HTTP on 127.0.0.1. The bugs worth catching here live in the wire layer, and an in-memory client wouldn't see a duplicate authorization header. Nothing leaves the machine and no API key is needed.

The demo starts the made-up fleet on loopback with one server deliberately down and puts the real gateway assembly in front of it, with identity stubbed. Then it prints what each step looks like from the client side:

- the namespaced tool list
- the one authorization header the upstream actually received
- the dead server's marker and its message
- the same search run by two people with different access
- the refusal text when someone calls a tool they can't have
- the cost table above, for the made-up fleet

To measure your own servers, point the benchmark at them:

```
python scripts/measure_schema_tokens.py --upstream inventory=https://inventory-mcp.example.com/mcp --upstream docs=https://docs-mcp.example.com/mcp --bearer "$TOKEN"
```

## Running it for real

Configuration is environment variables, listed in `.env.example`. You need an Entra app registration for the gateway with app roles named `<namespace>.read`, and the gateway has to be pre-authorized on each upstream's own app registration. On-Behalf-Of also needs a client secret. The gateway validates tokens in resource-server mode and never issues them. It refuses to start half-configured, so a missing secret or an identifier URI that isn't the `/mcp` URL stops the process at boot with the reason in the log. `tests/test_boot.py` launches it as a subprocess and checks both the happy path and those refusals.

Dependencies are pinned exactly. A fresh build that floated to newer `mcp` and `starlette` once dropped the caller's identity on every call through the production gateway.

## What's left out

The production version also has per-team tool allowlists, telemetry through [mcp-telemetry-kit](https://github.com/johngilligan2/mcp-telemetry-kit), and the deployment itself (reverse proxy, Compose stack, Entra provisioning scripts).

## License

MIT.
