"""Filesystem server in the shape of the reference MCP filesystem server:
every path is validated against an allowed root; deletion of a file asks a
human through MCP elicitation, deletion of a directory does not."""
# expect-verdict: FAIL_CRITICAL

import logging
import os
import shutil
from pathlib import Path

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("filesystem")
log = logging.getLogger(__name__)
ALLOWED_ROOT = Path("/srv/workspace").resolve()


def validate_path(path: str) -> Path:
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(ALLOWED_ROOT):
        raise ValueError(f"{path} is outside the workspace")
    return resolved


@mcp.tool()
def read_file(path: str) -> str:
    target = validate_path(path)
    log.info("read %s", target)
    return target.read_text()


@mcp.tool()
def write_file(path: str, content: str) -> str:
    target = validate_path(path)
    target.write_text(content)
    log.info("wrote %s", target)
    return "ok"


@mcp.tool()
async def delete_file(path: str, ctx: Context) -> str:
    target = validate_path(path)
    answer = await ctx.elicit(f"Delete {target}?", schema=Confirm)
    if answer.action != "accept":
        return "cancelled"
    try:
        os.remove(target)
    except OSError as exc:
        log.error("delete failed: %s", exc)
        return f"failed: {exc}"
    return "deleted"


@mcp.tool()
def delete_directory(path: str) -> str:
    target = validate_path(path)
    shutil.rmtree(target)  # expect: human-oversight, error-handling
    log.info("removed %s", target)
    return "removed"


@mcp.tool()
def move_file(source: str, destination: str) -> str:  # expect: input-validation
    src = validate_path(source)
    shutil.move(src, destination)
    return "moved"
