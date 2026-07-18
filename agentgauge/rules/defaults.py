"""Rule 6 of 6: Permissive defaults (10 points).

Inverted category: rules 1-5 ask "where risk exists, is a control present?"
-- this one asks "where a governance knob exists, is it set to the safe
side?" Sites are bindings of recognized flag names to boolean constants:
assignments, keyword arguments, and function-parameter defaults. Bindings
to non-constants are not sites; we can't judge a value we can't see.
"""

import ast

from agentgauge.astutils import FileContext
from agentgauge.models import Finding

RULE_ID = "permissive-defaults"
CATEGORY = "Permissive defaults"
WEIGHT = 10

# Matched against lowercased names with underscores/hyphens stripped, so
# auto_approve, AUTO_APPROVE and autoApprove all hit "autoapprove".
DANGEROUS_WHEN_TRUE = {
    "autoapprove", "autoconfirm", "autoaccept", "autorun", "autoexecute",
    "skipapproval", "skipconfirm", "skipconfirmation", "skipreview",
    "noconfirm", "noapproval",
    "allowall", "trustall", "unsafe",
    "disableauth", "disablesafety", "bypassapproval", "bypasssafety",
}

DANGEROUS_WHEN_FALSE = {
    "requireapproval", "approvalrequired",
    "requireconfirmation", "confirmationrequired", "requireconfirm",
    "requireauth", "authrequired",
    "requirehuman", "humanintheloop", "humanreview",
    "verify", "verifyssl", "sslverify",
    "safemode", "sandbox", "sandboxed",
}


def _collapsed(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "")


def _flag_bindings(tree: ast.AST):
    """Yield (name, value_node, lineno) for every name-to-value binding:
    assignments, keyword arguments, and parameter defaults."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    yield target.id, node.value, node.lineno
                elif isinstance(target, ast.Attribute):
                    yield target.attr, node.value, node.lineno
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                yield node.target.id, node.value, node.lineno
            elif isinstance(node.target, ast.Attribute):
                yield node.target.attr, node.value, node.lineno
        elif isinstance(node, ast.keyword) and node.arg is not None:
            yield node.arg, node.value, node.value.lineno
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            pos = [*node.args.posonlyargs, *node.args.args]
            defaults = node.args.defaults
            for arg, default in zip(pos[len(pos) - len(defaults):], defaults):
                yield arg.arg, default, arg.lineno
            for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                if default is not None:
                    yield arg.arg, default, arg.lineno


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []
    for name, value, lineno in _flag_bindings(ctx.tree):
        if not (isinstance(value, ast.Constant) and isinstance(value.value, bool)):
            continue
        collapsed = _collapsed(name)
        if collapsed in DANGEROUS_WHEN_TRUE:
            safe = value.value is False
        elif collapsed in DANGEROUS_WHEN_FALSE:
            safe = value.value is True
        else:
            continue
        sites += 1
        if safe:
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=lineno,
                message=f"permissive default: '{name}={value.value}' "
                        "disables a safety control",
                fix=f"Set {name}={not value.value} and require explicit "
                    "per-action opt-in instead",
            )
        )
    return sites, passed, findings
