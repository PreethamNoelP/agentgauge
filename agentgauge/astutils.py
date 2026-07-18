"""AST helpers shared by every agentgauge rule.

Everything here answers one of three questions about a parsed file:
  1. What is this call actually calling?   -> dotted_name / call_name
  2. Is that call a sensitive action?      -> sensitive_label / iter_sensitive_calls
  3. What surrounds this node in the tree? -> build_parent_map / enclosing_function
"""

import ast
import re
from dataclasses import dataclass

# Full dotted names that always mean a sensitive action. Matched exactly,
# so harmless lookalikes (platform.system, df.eval) are not flagged.
SENSITIVE_EXACT: dict[str, str] = {
    # file destruction
    "os.remove": "file delete",
    "os.unlink": "file delete",
    "os.rmdir": "file delete",
    "shutil.rmtree": "file delete",
    # shell / process execution
    "os.system": "shell exec",
    "os.popen": "shell exec",
    "subprocess.run": "shell exec",
    "subprocess.call": "shell exec",
    "subprocess.check_call": "shell exec",
    "subprocess.check_output": "shell exec",
    "subprocess.Popen": "shell exec",
    # dynamic code execution
    "eval": "code exec",
    "exec": "code exec",
    # state-changing HTTP
    "requests.delete": "remote delete",
}

# Bare method names distinctive enough to flag on ANY receiver
# (client.rmtree(...), gateway.charge(...)). Deliberately excludes generic
# names like "run", "call", "delete", "system" -- those would flag half of
# any normal repo.
SENSITIVE_SUFFIX: dict[str, str] = {
    "rmtree": "file delete",
    "delete_file": "file delete",
    "remove_file": "file delete",
    "Popen": "shell exec",
    "check_output": "shell exec",
    "charge": "payment",
    "create_payment": "payment",
    "send_payment": "payment",
    "transfer_funds": "payment",
    "refund": "payment",
    "payout": "payment",
}

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map every node to its parent. AST nodes have no .parent attribute,
    so upward questions ("am I inside a try?") need this built once per file."""
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def dotted_name(node: ast.expr) -> str | None:
    """Unwind an Attribute chain: the AST for `os.path.join` becomes the
    string "os.path.join". Returns None for anything dynamic (subscripts,
    call results, lambdas) whose target a static scan cannot know."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def call_name(call: ast.Call) -> str | None:
    """Dotted name of what a Call node is calling, or None if dynamic."""
    return dotted_name(call.func)


def sensitive_label(call: ast.Call) -> str | None:
    """Action label ("file delete", "shell exec", ...) if this call looks
    sensitive, else None. Exact table first, then the suffix table."""
    name = call_name(call)
    if name is None:
        return None
    if name in SENSITIVE_EXACT:
        return SENSITIVE_EXACT[name]
    return SENSITIVE_SUFFIX.get(name.rsplit(".", 1)[-1])


def iter_sensitive_calls(tree: ast.AST):
    """Yield (call_node, action_label) for every sensitive call in the tree."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            label = sensitive_label(node)
            if label is not None:
                yield node, label


def enclosing_function(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> FunctionNode | None:
    """Climb the parent map to the nearest def/async def containing `node`."""
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parents.get(current)
    return None


@dataclass
class FileContext:
    """Everything a rule needs to know about one parsed file. Rules all
    share one signature: check(ctx) -> (sites, passed, findings)."""

    path: str
    tree: ast.AST
    parents: dict[ast.AST, ast.AST]

    @classmethod
    def from_source(cls, source: str, path: str = "<memory>") -> "FileContext":
        tree = ast.parse(source)
        return cls(path=path, tree=tree, parents=build_parent_map(tree))


def iter_functions(tree: ast.AST):
    """Yield every def/async def in the tree, nested ones included."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def iter_identifiers(scope: ast.AST):
    """Yield every identifier-ish string in a subtree: variable names,
    attribute accesses, def/class names, parameters, keyword-arg names.
    Rules match governance vocabulary ("approv", "throttle") against these."""
    for node in ast.walk(scope):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name
        elif isinstance(node, ast.arg):
            yield node.arg
        elif isinstance(node, ast.keyword) and node.arg is not None:
            yield node.arg


def name_tokens(name: str) -> set[str]:
    """Split a (possibly dotted) name into lowercase word tokens:
    'audit_log' -> {'audit', 'log'}; 'logger.info' -> {'logger', 'info'}.
    Token matching avoids substring accidents like 'log' inside 'login'."""
    return {t for t in re.split(r"[._]", name.lower()) if t}


def is_tool_function(fn: FunctionNode) -> bool:
    """A "tool function" is what per-function governance rules apply to:
    either it is decorated as a tool (@mcp.tool(), @tool, ...) or it
    performs a sensitive action itself."""
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = dotted_name(target)
        if name is not None and "tool" in name_tokens(name):
            return True
    return next(iter_sensitive_calls(fn), None) is not None
