"""Deliberately vulnerable MCP server fixture.

Never imported or executed -- only parsed by the scanner. Every one of the
six agentgauge categories must produce at least one finding here, and every
shape below is one that a previous version of agentgauge scored as clean.
If a rule stops firing on this file, its detection has regressed.
"""

import asyncio
import pickle
import shutil
import subprocess
from pathlib import Path
from subprocess import run  # plain from-import: the bare name "run"

auto_approve = True
SETTINGS = {"skip_confirmation": True}

rm = shutil.rmtree  # a sink rebound to another name


@mcp.tool()
def delete_path(path):
    """No approval, no logging, no rate limit, no try, no validation."""
    shutil.rmtree(path)


@mcp.tool()
def run_command(cmd):
    """Nothing between the model and your shell."""
    return subprocess.run(cmd, shell=True)


@mcp.tool()
def run_via_from_import(cmd):
    """The bare name `run` is not in the suffix table; only alias
    resolution catches this."""
    return run(cmd, shell=True)


@mcp.tool()
def wipe_via_rebinding(path):
    """`rm` resolves to shutil.rmtree only through assignment aliasing."""
    rm(path)


@mcp.tool()
def unlink_file(path):
    """pathlib deletion through a dynamic receiver."""
    Path(path).unlink()


@mcp.tool()
async def shell_async(cmd):
    """The asyncio equivalent of subprocess -- what an async agent server
    actually reaches for."""
    return await asyncio.create_subprocess_shell(cmd)


@mcp.tool()
def load_state(path):
    """Deserialization as code execution."""
    return pickle.loads(open(path, "rb").read())


@mcp.tool()
def evaluate(expression):
    """Arbitrary code execution as a service."""
    return eval(expression)


def helper_that_mentions_approval():
    """Bait: this function's approval vocabulary must not satisfy the
    module-level sink below, which runs in a different scope."""
    if request_approval("anything"):
        return True
    return False


subprocess.check_call(["setup.sh"])  # module-level sink, nothing gating it


def watch_forever():
    while True:
        process_next()
