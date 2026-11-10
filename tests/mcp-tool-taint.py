# Test fixtures for rules/mcp-tool-taint.yaml
# Run: semgrep --test --config rules/ tests/
from mcp.server.fastmcp import FastMCP
import os
import subprocess
import sqlite3
import requests

mcp = FastMCP("demo")
db = sqlite3.connect("app.db")


def validate_url(u: str) -> str:
    if not u.startswith("https://api.internal/"):
        raise ValueError("blocked")
    return u


def validate_path(p: str) -> str:
    base = os.path.realpath("./vault")
    full = os.path.realpath(os.path.join(base, p))
    if not full.startswith(base + os.sep):
        raise ValueError("traversal")
    return full


# --- command injection ------------------------------------------------------
@mcp.tool()
def ping(host: str) -> str:
    # ruleid: mcp-tool-arg-command-injection
    os.system("ping -c1 " + host)
    return "ok"


@mcp.tool()
def listing(path: str) -> str:
    # ruleid: mcp-tool-arg-command-injection
    subprocess.run("ls " + path, shell=True)
    return "ok"


@mcp.tool()
def upper(msg: str) -> str:
    # ok: mcp-tool-arg-command-injection
    return msg.upper()


# --- SQL injection ----------------------------------------------------------
@mcp.tool()
def find_user(name: str) -> str:
    cur = db.cursor()
    # ruleid: mcp-tool-arg-sql-injection
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return "ok"


@mcp.tool()
def find_user_safe(name: str) -> str:
    cur = db.cursor()
    # ok: mcp-tool-arg-sql-injection
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return "ok"


# --- SSRF -------------------------------------------------------------------
@mcp.tool()
def fetch(url: str) -> str:
    # ruleid: mcp-tool-arg-ssrf
    return requests.get(url).text


@mcp.tool()
def fetch_safe(url: str) -> str:
    # ok: mcp-tool-arg-ssrf
    return requests.get(validate_url(url)).text


# --- path traversal ---------------------------------------------------------
@mcp.tool()
def read_doc(path: str) -> str:
    # ruleid: mcp-tool-arg-path-traversal
    with open(path) as f:
        return f.read()


@mcp.tool()
def read_doc_safe(path: str) -> str:
    # ok: mcp-tool-arg-path-traversal
    with open(validate_path(path)) as f:
        return f.read()
