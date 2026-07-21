"""Rule 1 of 6: Human oversight (25 points).

Heuristic: every sensitive call (file delete, shell exec, payment, ...)
must have a human-approval *signal* in an *enforcing position* within its
enclosing scope: the identifier is the callee of a Call, appears in the
test of an if/while/assert, or names a decorator -- not merely assigned
to or passed as a keyword, which would count a dead variable no one
checks. Position-based, not flow-based: we don't trace where a tested
value's truthiness ultimately comes from (e.g. a hardcoded
`approved = True` feeding a real `if approved:` still passes).
"""

import ast

from agentgauge.astutils import (
    FileContext,
    call_name,
    dotted_name,
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


def _mentions_marker(name: str) -> bool:
    lowered = name.lower()
    return lowered == "input" or any(marker in lowered for marker in APPROVAL_MARKERS)


def _decorator_name(dec: ast.expr) -> str | None:
    target = dec.func if isinstance(dec, ast.Call) else dec
    return dotted_name(target)


def _has_approval_signal(scope: ast.AST) -> bool:
    for node in ast.walk(scope):
        if isinstance(node, ast.Call):
            name = call_name(node)
            if name is not None and _mentions_marker(name):
                return True
        elif isinstance(node, (ast.If, ast.While)):
            if any(_mentions_marker(i) for i in iter_identifiers(node.test)):
                return True
        elif isinstance(node, ast.Assert):
            if any(_mentions_marker(i) for i in iter_identifiers(node.test)):
                return True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                name = _decorator_name(dec)
                if name is not None and _mentions_marker(name):
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
