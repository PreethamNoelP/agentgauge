"""Rule 4 of 6: Error handling (15 points).

Two kinds of sites feed this category:
  1. Unconditional loops (while True / while 1): must contain an exit that
     actually leaves them -- a break at THIS loop's level (not a nested
     loop's), a return/raise (not inside a nested def), or sys.exit.
  2. Sensitive calls: must sit inside the *body* of a try. Handlers, else
     and finally don't count -- code there isn't protected by that try.
"""

import ast

from agentgauge.astutils import FileContext, call_name, iter_sensitive_calls
from agentgauge.models import Finding

RULE_ID = "error-handling"
CATEGORY = "Error handling"
WEIGHT = 15

_EXIT_CALLS = {"sys.exit", "os._exit", "exit", "quit"}
_TRY_TYPES = (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)


def _is_unconditional_loop(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.While)
        and isinstance(node.test, ast.Constant)
        and bool(node.test.value)
    )


def _loop_can_exit(loop: ast.While) -> bool:
    """True if the loop contains an exit that actually leaves it. A break
    inside a nested loop only exits that inner loop; a return inside a
    nested def doesn't unwind this loop at all -- neither counts."""

    def scan(node: ast.AST, in_nested_loop: bool) -> bool:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, (ast.Return, ast.Raise)):
                return True
            if isinstance(child, ast.Break) and not in_nested_loop:
                return True
            if isinstance(child, ast.Call) and call_name(child) in _EXIT_CALLS:
                return True
            nested = in_nested_loop or isinstance(
                child, (ast.For, ast.AsyncFor, ast.While)
            )
            if scan(child, nested):
                return True
        return False

    return scan(loop, False)


def _in_try_body(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Climb the parent map; when we hit a Try, `prev` is the direct child
    we climbed through, which tells us WHICH compartment held the node."""
    prev, current = node, parents.get(node)
    while current is not None:
        if isinstance(current, _TRY_TYPES) and any(prev is s for s in current.body):
            return True
        prev, current = current, parents.get(current)
    return False


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []

    for node in ast.walk(ctx.tree):
        if not _is_unconditional_loop(node):
            continue
        sites += 1
        if _loop_can_exit(node):
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=node.lineno,
                message="unbounded 'while True' loop with no break, return or raise",
                fix="Add a termination path: a max-iteration counter, a timeout, "
                    "or a break on a stop signal",
            )
        )

    for call, label in iter_sensitive_calls(ctx.tree):
        sites += 1
        if _in_try_body(call, ctx.parents):
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=call.lineno,
                message=f"{label} call '{call_name(call)}' is not wrapped in try/except",
                fix="Wrap the call in try/except; log the failure and return a "
                    "safe error to the caller instead of crashing",
            )
        )

    return sites, passed, findings
