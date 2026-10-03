"""A notes server written the way MCP tutorials teach: the parameter is
called `name`, not `path`, and it goes straight into a file path."""
# expect-verdict: FAIL_CRITICAL

import os
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES = Path.home() / "notes"


@mcp.tool()
def list_notes() -> list[str]:
    return [p.name for p in NOTES.glob("*.md")]


@mcp.tool()
def read_note(name: str) -> str:  # expect: input-validation
    return (NOTES / name).read_text()


@mcp.tool()
def delete_note(name: str) -> str:  # expect: input-validation
    os.remove(NOTES / name)  # expect: human-oversight, error-handling
    return "deleted"


@mcp.tool()
def safe_read(name: str) -> str:
    if "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("bad note name")
    return (NOTES / name).read_text()


@mcp.tool()
def git_sync(message: str) -> str:  # known-fp: input-validation
    # The message is the value of -m, one argv element, never a shell
    # string: not an injection. Committing still changes state unapproved.
    subprocess.run(["git", "-C", str(NOTES), "commit", "-am", message], check=True)  # expect: human-oversight, error-handling
    return "synced"
