"""A plausible MCP server: some tools fully governed, a few with a real gap.

Parse-only demo content for the agentgauge playground -- never imported or
executed. Undefined names (`mcp`, `logger`, `request_approval`, `audit_log`,
`rate_limiter`, `throttle`, `payments_client`, `db`) are intentional, the
same way tests/fixtures/*.py leaves them undefined: a parser doesn't need
them to exist. Unlike those two fixtures (deliberately 0/100 and 100/100,
built to pin regressions in CI), this one is meant to look like a real
server someone actually shipped -- good instincts in most places, a few
concrete things still worth fixing.
"""

import subprocess
import shutil

require_approval = True
LEGACY_SETTINGS = {"skip_confirmation": True}  # left over from an old build

ALLOWED_DIAGNOSTIC_COMMANDS = {"uptime", "df", "ping"}


@mcp.tool()
def search_customer_records(query):
    """Look up customer records by a search query. No destructive sink here
    -- just the fully-governed baseline the other tools are compared to."""
    if not request_approval("search", query):
        return None
    rate_limiter.acquire()
    if not query.isalnum():
        raise ValueError("query must be alphanumeric")
    try:
        results = db.search(query)
    except OSError as exc:
        logger.error("search failed: %s", exc)
        return None
    audit_log("search_customer_records", query)
    return results


@mcp.tool()
def send_refund(order_id, amount):
    """Refund a customer through the payments provider. Approved, logged,
    and wrapped -- but nothing here stops it from being called 10,000
    times a second."""
    if not request_approval("refund", order_id):
        return False
    try:
        payments_client.transfer_funds(order_id, amount)
    except OSError as exc:
        logger.error("refund failed: %s", exc)
        return False
    audit_log("send_refund", order_id, amount)
    return True


@mcp.tool()
def delete_backup(path):
    """Delete an old backup archive. Approved, rate-limited, and wrapped --
    but `path` itself is never checked before it reaches rmtree."""
    approved = request_approval("delete_backup", path)
    if not approved:
        return False
    throttle.wait()
    try:
        shutil.rmtree(path)
    except OSError as exc:
        logger.error("delete failed: %s", exc)
        return False
    audit_log("delete_backup", path)
    return True


@mcp.tool()
def run_diagnostic_script(cmd):
    """Run an allowlisted diagnostic command on the host. The allowlist
    check is real, and it's approved and rate-limited -- but the call
    itself is naked (no try/except) and nothing records that it ran."""
    if not request_approval("run_diagnostic", cmd):
        return None
    rate_limiter.acquire()
    if cmd not in ALLOWED_DIAGNOSTIC_COMMANDS:
        raise ValueError("command not allowlisted")
    return subprocess.run(cmd, shell=True)
