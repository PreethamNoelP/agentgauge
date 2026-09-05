"""Rule 1 of 6: Human oversight (25 points).

Heuristic: every sensitive call (file delete, shell exec, payment, ...)
must have a human-approval *signal* in an *enforcing position* within its
enclosing scope: the identifier is the callee of a Call, appears in the
test of an if/while/assert, or names a decorator -- not merely assigned
to or passed as a keyword, which would count a dead variable no one
checks. Position-based, not flow-based: we don't trace where a tested
value's truthiness ultimately comes from (e.g. a hardcoded
`approved = True` feeding a real `if approved:` still passes).

"Scope" means the *same* execution scope (see astutils.iter_scope), not
the whole subtree. A check written inside some other function in the file
does not run when a module-level call executes, so it must not satisfy it.
"""

import ast

from agentgauge.astutils import (
    FileContext,
    call_name,
    dotted_name,
    enclosing_function,
    is_critical,
    iter_scope,
)
from agentgauge.models import Finding

RULE_ID = "human-oversight"
CATEGORY = "Human oversight"
WEIGHT = 25

# Stems on purpose: "approv" catches approve/approval/approved/preapproved.
APPROVAL_MARKERS = ("approv", "confirm", "consent", "authoriz", "human")


def _mentions_marker(name: str, extra_markers: tuple[str, ...]) -> bool:
    lowered = name.lower()
    markers = APPROVAL_MARKERS + extra_markers
    return lowered == "input" or any(marker in lowered for marker in markers)


def _decorator_name(dec: ast.expr) -> str | None:
    target = dec.func if isinstance(dec, ast.Call) else dec
    return dotted_name(target)


def _test_markers(test: ast.expr):
    """Identifiers actually referenced by a test expression: Name and
    Attribute nodes only -- not keyword-argument names of a call inside
    it. A keyword name describes an unrelated call's own parameter, not
    something the test enforces on: `if configure(require_approval=False):`
    must not pass just because that call happens to have a keyword spelled
    like the approval vocabulary (the same shape already fails as a bare
    statement; iter_identifiers would let it back in via the `if`)."""
    for node in ast.walk(test):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr


def _has_approval_signal(
    scope: ast.AST, extra_markers: tuple[str, ...], aliases: dict[str, str]
) -> bool:
    for node in iter_scope(scope):
        if isinstance(node, ast.Call):
            name = call_name(node, aliases)
            if name is not None and _mentions_marker(name, extra_markers):
                return True
        elif isinstance(node, (ast.If, ast.While)):
            if any(_mentions_marker(i, extra_markers) for i in _test_markers(node.test)):
                return True
        elif isinstance(node, ast.Assert):
            if any(_mentions_marker(i, extra_markers) for i in _test_markers(node.test)):
                return True
    # iter_scope does not descend into nested defs, so the only FunctionDef
    # it yields is `scope` itself -- this branch reads that function's own
    # decorators (@requires_approval), which do gate it.
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for dec in scope.decorator_list:
            name = _decorator_name(dec)
            if name is not None and _mentions_marker(name, extra_markers):
                return True
    return False


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []
    extra_markers = ctx.config.approval_markers
    # One scope answers identically for every sensitive call it contains, and
    # a single function can hold hundreds of them -- without this cache the
    # rule re-walks the whole scope per call, which is quadratic (a 800-call
    # module took ~6s before, ~0.05s after).
    signal_cache: dict[int, bool] = {}
    for call, label in ctx.sensitive_calls:
        sites += 1
        fn = enclosing_function(call, ctx.parents)
        scope = fn if fn is not None else ctx.tree
        has_signal = signal_cache.get(id(scope))
        if has_signal is None:
            has_signal = _has_approval_signal(scope, extra_markers, ctx.import_aliases)
            signal_cache[id(scope)] = has_signal
        if has_signal:
            passed += 1
            continue
        where = f"in '{fn.name}'" if fn is not None else "at module level"
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=call.lineno,
                message=f"{label} call '{call_name(call, ctx.import_aliases)}' {where} "
                        "has no human-approval check in scope",
                fix="Gate the call behind an explicit approval, e.g. "
                    "`if not request_approval(...): return` before it executes",
                critical=is_critical(label),
            )
        )
    return sites, passed, findings
