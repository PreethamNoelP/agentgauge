"""Rule 5 of 6: Tool scope & input validation (15 points).

Heuristic: risky-looking parameters of tool functions (path, cmd, query,
url, ...) must be referenced by some validation construct inside the
function: an if/while/assert test that mentions the parameter, or a call
with validation vocabulary (validate, sanitize, check, quote, ...) that
receives it. Name-based on BOTH sides: a risky value in an innocently
named parameter is invisible, and an unrecognized validator doesn't count.
"""

import ast

from agentgauge.astutils import (
    FileContext,
    call_name,
    dotted_name,
    is_tool_function,
    iter_functions,
    name_tokens,
)
from agentgauge.models import Finding

RULE_ID = "input-validation"
CATEGORY = "Tool scope & input validation"
WEIGHT = 15

RISKY_PARAM_TOKENS = {
    "path", "file", "filename", "dir", "directory",
    "cmd", "command", "shell",
    "query", "sql",
    "url", "uri", "host", "endpoint",
    "target", "dest", "destination",
}

VALIDATION_TOKENS = {
    "validate", "validated", "validation",
    "sanitize", "sanitized",
    "check", "checked",
    "verify", "verified",
    "allowed", "allowlist", "whitelist",
    "escape", "quote",
}


def _mentions(node: ast.AST, param: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == param for n in ast.walk(node))


def _is_validated(fn: ast.AST, param: str, validation_tokens: frozenset[str]) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, (ast.If, ast.While)) and _mentions(node.test, param):
            return True
        if isinstance(node, ast.Assert) and _mentions(node.test, param):
            return True
        if isinstance(node, ast.Call):
            name = call_name(node)
            if (
                name is not None
                and name_tokens(name) & validation_tokens
                and _mentions(node, param)
            ):
                return True
    return False


def _annotation_is_constrained(annotation: ast.expr | None) -> bool:
    """Type-annotation evidence of validation: `Literal[...]` restricts a
    parameter to a closed set of values by construction, and `Annotated[T,
    Field(...)]` (the FastMCP/Pydantic idiom for declaring pattern/length/
    range constraints) carries a validator the AST can see even though our
    name-based checks below never will. Presence of the construct counts as
    proof -- reading Field's own constraint arguments would need to resolve
    values through imports we can't statically guarantee, so we trust the
    declaration the same way rule 6 trusts a boolean literal."""
    if not isinstance(annotation, ast.Subscript):
        return False
    base = dotted_name(annotation.value)
    if base is None:
        return False
    base = base.rsplit(".", 1)[-1]
    if base == "Literal":
        return True
    if base == "Annotated":
        metadata = annotation.slice
        elts = metadata.elts if isinstance(metadata, ast.Tuple) else [metadata]
        for elt in elts:
            if isinstance(elt, ast.Call):
                name = call_name(elt)
                if name is not None and name.rsplit(".", 1)[-1] == "Field":
                    return True
    return False


def _risky_params(fn, risky_param_tokens: frozenset[str]):
    for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]:
        if arg.arg in ("self", "cls"):
            continue
        if name_tokens(arg.arg) & risky_param_tokens:
            yield arg


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []
    validation_tokens = VALIDATION_TOKENS | ctx.config.validation_tokens
    risky_param_tokens = RISKY_PARAM_TOKENS | ctx.config.risky_param_tokens
    for fn in iter_functions(ctx.tree):
        if not is_tool_function(fn, ctx.import_aliases):
            continue
        for arg in _risky_params(fn, risky_param_tokens):
            sites += 1
            if _is_validated(fn, arg.arg, validation_tokens) or _annotation_is_constrained(
                arg.annotation
            ):
                passed += 1
                continue
            findings.append(
                Finding(
                    rule=RULE_ID,
                    file=ctx.path,
                    line=arg.lineno,
                    message=f"risky parameter '{arg.arg}' of tool "
                            f"'{fn.name}' is used without validation",
                    fix="Validate before use: allowlist or prefix check "
                        "(`if not path.startswith(SAFE_ROOT): raise`) or a "
                        "sanitizer (`shlex.quote(cmd)`)",
                )
            )
    return sites, passed, findings
