"""Deliberately clean MCP server fixture.

Never imported or executed -- only parsed by the scanner. This file must
score exactly 100.0 with zero findings. If any rule starts flagging the
legitimate governance patterns below, that rule has developed a false
positive and this fixture catches it.
"""

import asyncio
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Annotated, Literal

require_approval = True
SETTINGS = {"skip_confirmation": False, "human_in_the_loop": True}

SAFE_ROOT = "/workspaces/"
ALLOWED_COMMANDS = {"ls", "cat", "echo"}


@mcp.tool()
def delete_path(path):
    if not path.startswith(SAFE_ROOT):
        raise ValueError("path outside sandbox")
    if not request_approval("delete", path):
        return False
    rate_limiter.acquire()
    try:
        shutil.rmtree(path)
    except OSError as exc:
        logger.error("delete failed: %s", exc)
        return False
    audit_log("delete_path", path)
    return True


@mcp.tool()
def run_command(cmd):
    if cmd.split()[0] not in ALLOWED_COMMANDS:
        raise ValueError("command not allowlisted")
    if not request_approval("run", cmd):
        return False
    throttle.wait()
    try:
        result = subprocess.run(shlex.quote(cmd), shell=False)
    except OSError as exc:
        logger.error("command failed: %s", exc)
        return False
    audit_log("run_command", cmd)
    return result


@mcp.tool()
async def run_async(cmd: Annotated[str, Field(pattern=r"^[a-z]+$")]):
    """A governed async tool: the asyncio sink is as gated as the blocking
    one, and the parameter's constraint lives in its annotation."""
    if not await request_approval("run_async", cmd):
        return None
    await rate_limiter.acquire()
    try:
        proc = await asyncio.create_subprocess_exec(cmd)
    except OSError as exc:
        logger.error("spawn failed: %s", exc)
        return None
    audit_log("run_async", cmd)
    return proc


@mcp.tool()
def remove_artifact(target: Literal["build", "dist"]):
    """Deletion through pathlib, with the target restricted by type to a
    closed set of values -- no runtime check needed or possible to add."""
    if not request_approval("remove_artifact", target):
        return False
    throttle.wait()
    try:
        Path(SAFE_ROOT, target).unlink()
    except OSError as exc:
        logger.error("unlink failed: %s", exc)
        return False
    audit_log("remove_artifact", target)
    return True


def watch_queue():
    while True:
        if queue_empty():
            break
        process_next()
