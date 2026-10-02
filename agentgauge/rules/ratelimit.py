"""Rule 3 of 6: Rate limiting (15 points).

Every tool entry point must reference rate-limiting vocabulary -- in its
body, its decorators, or a function it calls: an identifier containing
"ratelimit", "throttle" or "limiter" (underscores ignored), or the
ratelimit library's @limits decorator. Reference-based: the rule confirms
the vocabulary is present, not that the limiter is configured correctly.

`assume_external_rate_limiting = true` marks the category not applicable
when a gateway limits calls outside the scanned code.
"""

import ast
from collections.abc import Iterable

from agentgauge.astutils import FileContext, iter_identifiers
from agentgauge.config import RuleConfig
from agentgauge.models import Finding

RULE_ID = "rate-limiting"
CATEGORY = "Rate limiting"
WEIGHT = 15

# Bare "limit" is deliberately absent: pagination params (limit=10) and SQL
# LIMIT would drown the rule in false passes.
RATE_MARKERS = ("ratelimit", "throttle", "limiter")


def mentions_rate_limit(
    fn: ast.AST, config: RuleConfig, scope: Iterable[ast.AST] | None = None
) -> bool:
    """True if `fn` references rate-limit vocabulary. With `scope` (the
    function's own-scope nodes), nested defs are skipped -- the call-graph
    summary covers those separately."""
    # Config entries are collapsed the same way identifiers are, so
    # "rate_limit" still matches "rate_limit_check".
    markers = RATE_MARKERS + tuple(m.replace("_", "") for m in config.rate_markers)
    idents = (
        (ident for node in scope for ident in _node_identifiers(node))
        if scope is not None else iter_identifiers(fn)
    )
    for ident in idents:
        collapsed = ident.lower().replace("_", "")
        if collapsed == "limits":  # the ratelimit library's @limits decorator
            return True
        if any(marker in collapsed for marker in markers):
            return True
    return False


def _node_identifiers(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, ast.keyword) and node.arg is not None:
        return [node.arg]
    return []


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    if ctx.config.assume_external_rate_limiting:
        return 0, 0, []

    sites, passed, findings = 0, 0, []
    for fn in ctx.functions:
        if fn not in ctx.tool_functions:
            continue
        sites += 1
        if mentions_rate_limit(fn, ctx.config) or ctx.rate_limited_via_calls(fn):
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=fn.lineno,
                column=fn.col_offset + 1,
                function=ctx.qualname(fn),
                message=f"tool function '{fn.name}' has no rate-limit "
                        "or throttle reference",
                fix="Apply a limiter, e.g. `@limiter.limit('10/minute')` or a "
                    "token-bucket check at the top of the function",
            )
        )
    return sites, passed, findings
