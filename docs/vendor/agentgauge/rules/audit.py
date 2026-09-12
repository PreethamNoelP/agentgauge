"""Rule 2 of 6: Audit logging (20 points).

Heuristic: every tool function must make at least one logging/audit call.
"Tool function" = decorated as a tool (@mcp.tool, @tool, ...) or performing
a sensitive action itself. A logging call is any call whose dotted name has
a log/logger/logging/audit token -- token match, so login() does not count.
"""

import ast

from agentgauge.astutils import (
    FileContext,
    call_name,
    name_tokens,
)
from agentgauge.models import Finding

RULE_ID = "audit-logging"
CATEGORY = "Audit logging"
WEIGHT = 20

LOG_TOKENS = frozenset(
    {"log", "logger", "logging", "logged", "audit", "auditing", "audited"}
)


def _makes_log_call(
    fn: ast.AST, log_tokens: frozenset[str], aliases: dict[str, str]
) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            # Alias-aware for the same reason the sink tables are: with
            # `from telemetry import audit_log as al`, the local spelling
            # `al(...)` carries none of the vocabulary the rule looks for.
            name = call_name(node, aliases)
            if name is not None and name_tokens(name) & log_tokens:
                return True
    return False


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []
    log_tokens = LOG_TOKENS | ctx.config.log_tokens
    for fn in ctx.functions:
        if fn not in ctx.tool_functions:
            continue
        sites += 1
        if _makes_log_call(fn, log_tokens, ctx.import_aliases):
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=fn.lineno,
                message=f"tool function '{fn.name}' makes no audit/log call",
                fix="Record the invocation, e.g. `logger.info(...)` or "
                    "`audit_log(actor, action, args)` inside the function",
            )
        )
    return sites, passed, findings
