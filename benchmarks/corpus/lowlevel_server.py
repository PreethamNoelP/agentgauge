"""An ops server on the low-level MCP SDK: one dispatch function, inputs in
an `arguments` dict."""
# expect-verdict: FAIL_CRITICAL

import logging
import shutil
import subprocess
from pathlib import Path

from mcp.server import Server
from mcp.types import TextContent

server = Server("ops")
log = logging.getLogger(__name__)
SERVICES = {"web", "worker"}


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    log.info("tool %s", name)
    if name == "read_log":
        path = arguments["path"]
        if not path.startswith("/var/log/app/"):
            raise ValueError("not an application log")
        return [TextContent(type="text", text=Path(path).read_text())]
    if name == "restart_service":
        service = arguments["service"]
        if service not in SERVICES:
            raise ValueError(f"unknown service {service!r}")
        subprocess.run(["systemctl", "restart", service], check=True)  # expect: human-oversight, error-handling
        return [TextContent(type="text", text="restarted")]
    if name == "purge_cache":
        target = arguments.get("target")  # expect: input-validation
        shutil.rmtree(target)  # expect: human-oversight, error-handling
        return [TextContent(type="text", text="purged")]
    raise ValueError(f"unknown tool {name}")
