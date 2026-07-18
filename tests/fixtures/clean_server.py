"""Deliberately clean MCP server fixture.

Never imported or executed -- only parsed by the scanner. This file must
score exactly 100.0 with zero findings. If any rule starts flagging the
legitimate governance patterns below, that rule has developed a false
positive and this fixture catches it.
"""

import shlex
import shutil
import subprocess

require_approval = True

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


def watch_queue():
    while True:
        if queue_empty():
            break
        process_next()
