"""Rule 1 of 6: Human oversight (25 points).

Heuristic: every sensitive call (file delete, shell exec, payment, ...)
must have a human-approval *signal* in its enclosing scope -- an identifier
mentioning approval/confirmation/consent, or a call to builtin input().
Presence-based, not flow-based: we check that approval vocabulary exists
near the dangerous call, not that it actually gates execution.
"""

import ast

from agentgauge.astutils import (
    FileContext,
    call_name,
    enclosing_function,
    iter_identifiers,
    iter_sensitive_calls,
)
from agentgauge.models import Finding

RULE_ID = "human-oversight"
CATEGORY = "Human oversight"
WEIGHT = 25

# Stems on purpose: "approv" catches approve/approval/approved/preapproved.
APPROVAL_MARKERS = ("approv", "confirm", "consent", "authoriz", "human")


def _has_approval_signal(scope: ast.AST) -> bool:
    for ident in iter_identifiers(scope):
        lowered = ident.lower()
        if lowered == "input":  # builtin input() is a human prompt
            return True
        if any(marker in lowered for marker in APPROVAL_MARKERS):
            return True
    return False


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []
    for call, label in iter_sensitive_calls(ctx.tree):
        sites += 1
        fn = enclosing_function(call, ctx.parents)
        scope = fn if fn is not None else ctx.tree
        if _has_approval_signal(scope):
            passed += 1
            continue
        where = f"in '{fn.name}'" if fn is not None else "at module level"
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=call.lineno,
                message=f"{label} call '{call_name(call)}' {where} "
                        "has no human-approval check in scope",
                fix="Gate the call behind an explicit approval, e.g. "
                    "`if not request_approval(...): return` before it executes",
            )
        )
    return sites, passed, findings
