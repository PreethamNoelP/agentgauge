"""Tools whose sensitive actions live in another module."""
# expect-verdict: FAIL_CRITICAL

import logging

import ops
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("projects")
log = logging.getLogger(__name__)
PROJECTS = {"alpha": "/srv/projects/alpha", "beta": "/srv/projects/beta"}


@mcp.tool()
def archive_project(name: str) -> str:
    if name not in PROJECTS:
        raise ValueError(f"unknown project {name!r}")
    if not request_approval(f"archive {name}"):
        return "declined"
    try:
        ops.remove_tree(PROJECTS[name])
    except OSError as exc:
        log.error("archive failed: %s", exc)
        return "failed"
    log.info("archived %s", name)
    return "archived"


@mcp.tool()
def clear_tmp(path: str) -> str:  # expect: input-validation
    log.info("clear %s", path)
    ops.remove_file(path)
    return "cleared"
