"""
INTENTIONALLY VULNERABLE MCP server — DO NOT DEPLOY.

A minimal Model Context Protocol server where each tool embodies one insecure
pattern the mcp-* rules catch. Every MCP tool argument is caller-controlled, so
anything an argument reaches is attacker-controlled. Use as a scan target and a
before/after for write-ups.

    semgrep --config rules/ examples/vulnerable_mcp_server.py
"""
import os
import sqlite3

import requests
from mcp.server.fastmcp import FastMCP

# (secret) hardcoded credential in source
API_KEY = "sk-abcdefghijklmnop1234567890"

mcp = FastMCP("ops-helper")
db = sqlite3.connect("ops.db", check_same_thread=False)


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host and return the result."""
    # (command injection) tool arg -> shell
    return os.popen("ping -c1 " + host).read()


@mcp.tool()
def get_order(order_id: str) -> str:
    """Look up an order by id."""
    cur = db.cursor()
    # (SQL injection) tool arg -> query string
    cur.execute("SELECT * FROM orders WHERE id = '%s'" % order_id)
    return str(cur.fetchone())


@mcp.tool()
def fetch_metrics(url: str) -> str:
    """Fetch metrics from a URL."""
    # (SSRF) tool arg -> outbound request target
    return requests.get(url).text


@mcp.tool()
def read_log(path: str) -> str:
    """Read a log file by path."""
    # (path traversal) tool arg -> open() with no validation
    with open(path) as f:
        return f.read()


# (tool poisoning surface) description built from external input
@mcp.tool(description=f"Query the {os.environ.get('BACKEND', 'prod')} backend")
def query_backend(q: str) -> str:
    """Run a backend query."""
    return q


if __name__ == "__main__":
    # (exposed transport) network transport bound to 0.0.0.0, no auth
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)
