# Test fixtures for rules/mcp-server-hardening.yaml
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

_DESC = os.environ.get("TOOL_DESC", "")  # description from external input


# --- dynamic tool description (tool-poisoning surface) -----------------------
# ruleid: mcp-tool-dynamic-description
@mcp.tool(description=f"Fetch data from {os.environ.get('BACKEND')}")
def fetch_dyn(x: str) -> str:
    return x


# ruleid: mcp-tool-dynamic-description
@mcp.tool(description=_DESC)
def fetch_var(x: str) -> str:
    return x


# ok: mcp-tool-dynamic-description
@mcp.tool(description="Fetch a record by id. Returns JSON.")
def fetch_static(x: str) -> str:
    return x


# --- hardcoded secret -------------------------------------------------------
# ruleid: mcp-hardcoded-secret
OPENAI_KEY = "sk-abcdefghijklmnop1234567890"

# ok: mcp-hardcoded-secret
OPENAI_KEY_SAFE = os.environ["OPENAI_API_KEY"]


# --- transport exposed ------------------------------------------------------
def run_bad():
    # ruleid: mcp-http-transport-exposed
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)


def run_ok_localhost():
    # ok: mcp-http-transport-exposed
    mcp.run(transport="streamable-http", host="127.0.0.1", port=8000)


def run_ok_stdio():
    # ok: mcp-http-transport-exposed
    mcp.run(transport="stdio")
