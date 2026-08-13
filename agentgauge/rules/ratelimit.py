"""Rule 3 of 6: Rate limiting (15 points).

Heuristic: every tool function must reference rate-limiting vocabulary in
its body or decorators: an identifier containing "ratelimit", "throttle" or
"limiter" (underscores ignored), or the ratelimit library's @limits
decorator. Reference-based: we confirm the vocabulary exists, not that the
limiter is correctly configured or even called.
"""

import ast

from agentgauge.astutils import (
    FileContext,
    is_tool_function,
    iter_functions,
    iter_identifiers,
)
from agentgauge.models import Finding

RULE_ID = "rate-limiting"
CATEGORY = "Rate limiting"
WEIGHT = 15

# Bare "limit" is deliberately absent: pagination params (limit=10) and SQL
# LIMIT would drown the rule in false passes.
RATE_MARKERS = ("ratelimit", "throttle", "limiter")


def _mentions_rate_limit(fn: ast.AST, extra_markers: tuple[str, ...]) -> bool:
    markers = RATE_MARKERS + extra_markers
    for ident in iter_identifiers(fn):
        collapsed = ident.lower().replace("_", "")
        if collapsed == "limits":  # the ratelimit library's @limits decorator
            return True
        if any(marker in collapsed for marker in markers):
            return True
    return False


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    if ctx.config.assume_external_rate_limiting:
        # Infra-level limiting (API gateway, global semaphore) is out of
        # view for a static scan; treat the category as not applicable
        # rather than penalizing every tool function for a control that
        # exists, just not in this source.
        return 0, 0, []

    sites, passed, findings = 0, 0, []
    # Collapsed the same way _mentions_rate_limit collapses the identifiers
    # it tests against, so an underscored config entry like "rate_limit"
    # still matches identifiers such as "rate_limit_check".
    extra_markers = tuple(m.replace("_", "") for m in ctx.config.rate_markers)
    for fn in iter_functions(ctx.tree):
        if not is_tool_function(fn, ctx.import_aliases):
            continue
        sites += 1
        if _mentions_rate_limit(fn, extra_markers):
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=fn.lineno,
                message=f"tool function '{fn.name}' has no rate-limit "
                        "or throttle reference",
                fix="Apply a limiter, e.g. `@limiter.limit('10/minute')` or a "
                    "token-bucket check at the top of the function",
            )
        )
    return sites, passed, findings
