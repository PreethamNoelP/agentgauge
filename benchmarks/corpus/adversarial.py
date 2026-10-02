"""Shapes that pass a vocabulary-near-the-sink check while gating nothing.
Each tool validates its input and handles errors, so the only real issue
in each is the missing (or fake) human approval."""
# expect-verdict: FAIL_CRITICAL

import logging
import os
import shutil
import subprocess

import humanize
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("adversarial")
log = logging.getLogger(__name__)
ROOT = "/srv/data/"
auto_approve = True  # expect: permissive-defaults


def _checked(path: str) -> str:
    if not path.startswith(ROOT):
        raise ValueError("outside root")
    return path


@mcp.tool()
def approval_after_the_sink(path: str) -> str:
    target = _checked(path)
    try:
        shutil.rmtree(target)  # expect: human-oversight
    except OSError:
        raise
    if not request_approval(f"delete {target}"):
        return "too late"
    return "done"


@mcp.tool()
def model_supplied_confirmation(path: str, confirm: bool = False) -> str:
    target = _checked(path)
    if not confirm:
        return "call again with confirm=True"
    try:
        shutil.rmtree(target)  # expect: human-oversight
    except OSError:
        raise
    return "done"


@mcp.tool()
def authorization_is_not_approval(path: str) -> str:
    target = _checked(path)
    if not current_user.is_authorized("delete"):
        raise PermissionError("denied")
    try:
        shutil.rmtree(target)  # expect: human-oversight
    except OSError:
        raise
    return "done"


@mcp.tool()
def hardcoded_approval(path: str) -> str:
    target = _checked(path)
    approved = True
    if approved:
        try:
            shutil.rmtree(target)  # expect: human-oversight
        except OSError:
            raise
    return "done"


@mcp.tool()
def vocabulary_lookalike(path: str) -> str:
    target = _checked(path)
    log.info("size %s", humanize.naturalsize(os.path.getsize(target)))
    try:
        shutil.rmtree(target)  # expect: human-oversight
    except OSError:
        raise
    return "done"


@mcp.tool()
def permissive_flag_as_gate(path: str) -> str:
    target = _checked(path)
    if auto_approve:
        try:
            shutil.rmtree(target)  # expect: human-oversight
        except OSError:
            raise
    return "done"


@mcp.tool()
def indirection(cmd: str) -> str:
    if cmd not in {"uptime", "df"}:
        raise ValueError("not allowed")
    try:
        return getattr(subprocess, "check_output")([cmd], text=True)  # expect: human-oversight
    except subprocess.CalledProcessError:
        raise


@mcp.tool()
def swallowed(path: str) -> str:
    target = _checked(path)
    if not request_approval(f"delete {target}"):
        return "declined"
    try:
        os.remove(target)  # expect: error-handling
    except Exception:
        pass
    return "done"
