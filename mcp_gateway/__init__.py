"""mcp-gateway: one MCP server fronting a fleet of MCP servers.

Two faces, and keeping them straight is the whole design:

  north  an MCP server and an OAuth *resource server*. Claude connects here and
         presents a token whose audience is THIS gateway's /mcp URL.
  south  an MCP client and an OAuth *client*. For every upstream call it asks
         Entra, on the caller's behalf, for a token whose audience is that
         upstream's own /mcp URL.

The inbound token is never forwarded. See mcp_gateway/upstreams.py for the
mechanics and tests/test_no_token_passthrough.py for the guard.
"""

__version__ = "0.1.0"
