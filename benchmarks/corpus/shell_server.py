"""Shell server: one allowlisted, approved command runner, and one
'script' tool that hands the model a bash prompt."""
# expect-verdict: FAIL_CRITICAL

import logging
import shlex
import subprocess

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("shell")
log = logging.getLogger(__name__)
ALLOWED = {"ls", "pwd", "git", "cat"}


@mcp.tool()
async def run_command(command: str, ctx: Context) -> str:
    argv = shlex.split(command)
    if not argv or argv[0] not in ALLOWED:
        raise ValueError(f"{command!r} is not allowlisted")
    answer = await ctx.elicit(f"Run {command}?", schema=Confirm)
    if answer.action != "accept":
        return "cancelled"
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.error("command failed: %s", exc)
        return f"failed: {exc}"
    log.info("ran %s", argv)
    return result.stdout


@mcp.tool()
def run_script(script: str) -> str:  # expect: input-validation
    log.info("running script")
    return subprocess.check_output(["bash", "-c", script], text=True)  # expect: human-oversight, error-handling
