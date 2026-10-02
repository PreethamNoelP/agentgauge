"""Deliberately clean MCP server fixture.

Never imported or executed -- only parsed by the scanner. This file must
score exactly 100.0 with zero findings. If any rule starts flagging the
legitimate governance patterns below, that rule has developed a false
positive and this fixture catches it.
"""

import asyncio
import os
import shlex
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Annotated, Literal

import requests

require_approval = True
SETTINGS = {"skip_confirmation": False, "human_in_the_loop": True}

SAFE_ROOT = "/workspaces/"
ALLOWED_COMMANDS = {"ls", "cat", "echo"}
LOOKUP_USER = "SELECT name FROM users WHERE id = ?"


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
    """The asyncio sink is as gated as the blocking one, and the parameter's
    constraint lives in its annotation."""
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
    """The target is restricted by type to a closed set of values."""
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


@mcp.tool()
async def drop_table(table: Literal["sessions", "cache"], ctx: Context):
    """MCP elicitation: the human answers out of band, and the framework-
    injected `ctx` is not a model-controlled argument."""
    answer = await ctx.elicit(message=f"Drop table {table}?", schema=Confirm)
    if answer.action != "accept":
        return "cancelled"
    await limiter.acquire()
    try:
        conn.execute(f"DROP TABLE {table}")
    except sqlite3.Error as exc:
        await ctx.error(f"drop failed: {exc}")
        return "failed"
    await ctx.info(f"dropped {table}")
    return "ok"


def _purge(path):
    """A helper that raises; every caller gates it and handles the error."""
    shutil.rmtree(path)


@mcp.tool()
def purge_cache(path):
    if not Path(path).resolve().is_relative_to(SAFE_ROOT):
        raise ValueError("path outside sandbox")
    if not request_approval("purge", path):
        return False
    rate_limiter.acquire()
    try:
        _purge(path)
    except OSError as exc:
        logger.error("purge failed: %s", exc)
        return False
    audit_log("purge_cache", path)
    return True


class ArchiveRequest(BaseModel):
    path: str = Field(pattern=r"^/workspaces/[\w./-]+$")
    destination: Literal["cold", "warm"] = "cold"


@mcp.tool()
def archive(request: ArchiveRequest):
    """Input-model fields are validated by their declarations."""
    if not request_approval("archive", request.path):
        return False
    rate_limiter.acquire()
    try:
        os.remove(request.path)
    except OSError as exc:
        logger.error("archive failed: %s", exc)
        return False
    audit_log("archive", request.path)
    return True


@server.call_tool()
async def handle_call(name, arguments):
    """Low-level MCP SDK dispatch, governed the same way."""
    path = arguments["path"]
    if not path.startswith(SAFE_ROOT):
        raise ValueError("path outside sandbox")
    if not await request_approval(name, path):
        return []
    await rate_limiter.acquire()
    try:
        os.remove(path)
    except OSError as exc:
        logger.error("delete failed: %s", exc)
        return []
    audit_log(name, path)
    return []


@mcp.tool()
def lookup_user(user_id: int):
    """A fixed, parameterized query and a non-payment HTTP call are not
    sensitive actions."""
    rate_limiter.acquire()
    logger.info("lookup %s", user_id)
    row = conn.execute(LOOKUP_USER, (user_id,)).fetchone()
    requests.post("https://hooks.example.com/lookup", json={"id": user_id})
    return row


@mcp.tool()
def watch_queue(queue_name: Literal["jobs"]):
    throttle.wait()
    logger.info("watching %s", queue_name)
    while True:
        if queue_empty(queue_name):
            break
        process_next(queue_name)


def rebuild_index():
    """Not reachable from any tool: maintenance code is out of scope."""
    subprocess.run(["make", "index"], check=True)
