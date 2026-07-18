"""Deliberately vulnerable MCP server fixture.

Never imported or executed -- only parsed by the scanner. Every one of the
six agentgauge categories must produce at least one finding here. If a rule
stops firing on this file, its detection has regressed.
"""

import shutil
import subprocess

auto_approve = True


@mcp.tool()
def delete_path(path):
    """No approval, no logging, no rate limit, no try, no validation."""
    shutil.rmtree(path)


@mcp.tool()
def run_command(cmd):
    """Nothing between the model and your shell."""
    return subprocess.run(cmd, shell=True)


@mcp.tool()
def evaluate(expression):
    """Arbitrary code execution as a service."""
    return eval(expression)


def watch_forever():
    while True:
        process_next()
