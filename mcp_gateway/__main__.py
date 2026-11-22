"""Container entry point: `python -m mcp_gateway`.

Exits non-zero on a configuration error rather than starting half-configured,
so a bad deploy is a container that will not come up with the reason in its
logs, instead of a running gateway that is subtly wrong.
"""

from __future__ import annotations

import logging
import sys

from .config import ConfigError
from .server import main

if __name__ == "__main__":
    try:
        main()
    except ConfigError as exc:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("mcp_gateway").error("configuration error: %s", exc)
        sys.exit(2)
