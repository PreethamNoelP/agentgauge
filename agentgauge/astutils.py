"""AST helpers shared by every agentgauge rule.

Everything here answers one of three questions about a parsed file:
  1. What is this call actually calling?   -> dotted_name / call_name
  2. Is that call a sensitive action?      -> sensitive_label / iter_sensitive_calls
  3. What surrounds this node in the tree? -> build_parent_map / enclosing_function
"""

import ast
import io
import re
import tokenize
from dataclasses import dataclass, field

from agentgauge.config import RuleConfig

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

# Consequence categories severe enough that a single missed approval gate
# must fail CI outright -- no volume of compliant sites elsewhere should be
# able to average this away (score averaging otherwise dilutes one
# catastrophic site across many low-risk ones; see issue #1).
CRITICAL_LABELS = {"file delete", "shell exec", "code exec", "payment", "remote delete"}


def is_critical(label: str) -> bool:
    """True if a sensitive-call label names a critical-consequence sink."""
    return label in CRITICAL_LABELS


FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map every node to its parent. AST nodes have no .parent attribute,
    so upward questions ("am I inside a try?") need this built once per file."""
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def dotted_name(node: ast.expr, aliases: dict[str, str] | None = None) -> str | None:
    """Unwind an Attribute chain: the AST for `os.path.join` becomes the
    string "os.path.join". Returns None for anything dynamic (subscripts,
    call results, lambdas) whose target a static scan cannot know.

    `aliases` (see build_import_aliases) resolves the chain's root through
    import aliasing: with {"sp": "subprocess"}, `sp.run` resolves to
    "subprocess.run" instead of the literal, alias-blind "sp.run"."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        base = node.id
        if aliases and base in aliases:
            resolved = aliases[base]
            return resolved if not parts else f"{resolved}.{'.'.join(reversed(parts))}"
        parts.append(base)
        return ".".join(reversed(parts))
    return None


def call_name(call: ast.Call, aliases: dict[str, str] | None = None) -> str | None:
    """Dotted name of what a Call node is calling, or None if dynamic."""
    return dotted_name(call.func, aliases)


def sensitive_label(call: ast.Call, aliases: dict[str, str] | None = None) -> str | None:
    """Action label ("file delete", "shell exec", ...) if this call looks
    sensitive, else None. Exact table first, then the suffix table."""
    name = call_name(call, aliases)
    if name is None:
        return None
    if name in SENSITIVE_EXACT:
        return SENSITIVE_EXACT[name]
    return SENSITIVE_SUFFIX.get(name.rsplit(".", 1)[-1])


def iter_sensitive_calls(tree: ast.AST, aliases: dict[str, str] | None = None):
    """Yield (call_node, action_label) for every sensitive call in the tree."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            label = sensitive_label(node, aliases)
            if label is not None:
                yield node, label


def build_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map every `as`-aliased import to what it actually names, so
    `import subprocess as sp; sp.run(...)` and
    `from shutil import rmtree as rt; rt(...)` resolve to "subprocess.run"
    and "shutil.rmtree" respectively instead of vanishing behind the alias
    (a documented blind spot -- see RULES.md). Only `as` imports are
    collected: a plain `import os.path` needs no alias, dotted_name already
    walks its Attribute chain. Relative `from . import x as y` is skipped --
    its target isn't a static dotted name we could resolve to anyway."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.level:
                continue
            for alias in node.names:
                if alias.asname is not None:
                    aliases[alias.asname] = f"{node.module}.{alias.name}"
    return aliases


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


# Matches "# agentgauge: ignore" (suppresses every rule on that line) or
# "# agentgauge: ignore[human-oversight, audit-logging]" (suppresses only the
# named rules) -- the same shape as flake8's "# noqa" / bandit's "# nosec".
_SUPPRESS_RE = re.compile(r"#\s*agentgauge:\s*ignore(?:\[([\w, -]+)\])?", re.IGNORECASE)


def _parse_suppressions(source: str) -> dict[int, frozenset[str] | None]:
    """Scan comment tokens (not a text search -- a string literal that
    happens to contain the marker must not count) for suppression markers.
    Maps line number -> None (suppress everything on that line) or a
    frozenset of rule ids (suppress only those). Best-effort: a source that
    parses with ast.parse but somehow fails to tokenize just gets no
    suppressions rather than aborting the scan."""
    suppressions: dict[int, frozenset[str] | None] = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type != tokenize.COMMENT:
                continue
            match = _SUPPRESS_RE.search(tok.string)
            if match is None:
                continue
            rules = match.group(1)
            if rules is None:
                suppressions[tok.start[0]] = None
            else:
                suppressions[tok.start[0]] = frozenset(
                    r.strip().lower() for r in rules.split(",") if r.strip()
                )
    except (tokenize.TokenError, SyntaxError, IndentationError):
        pass
    return suppressions


@dataclass
class FileContext:
    """Everything a rule needs to know about one parsed file. Rules all
    share one signature: check(ctx) -> (sites, passed, findings)."""

    path: str
    tree: ast.AST
    parents: dict[ast.AST, ast.AST]
    import_aliases: dict[str, str] = field(default_factory=dict)
    config: RuleConfig = field(default_factory=RuleConfig)
    suppressions: dict[int, frozenset[str] | None] = field(default_factory=dict)

    @classmethod
    def from_source(
        cls,
        source: str,
        path: str = "<memory>",
        config: RuleConfig | None = None,
    ) -> "FileContext":
        tree = ast.parse(source)
        return cls(
            path=path,
            tree=tree,
            parents=build_parent_map(tree),
            import_aliases=build_import_aliases(tree),
            config=config if config is not None else RuleConfig(),
            suppressions=_parse_suppressions(source),
        )

    def is_suppressed(self, rule: str, line: int) -> bool:
        """True if an `# agentgauge: ignore` comment on this line covers
        this rule -- either unqualified (covers every rule) or naming it
        explicitly by RULE_ID."""
        if line not in self.suppressions:
            return False
        rules = self.suppressions[line]
        return rules is None or rule in rules


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


def is_tool_function(fn: FunctionNode, aliases: dict[str, str] | None = None) -> bool:
    """A "tool function" is what per-function governance rules apply to:
    either it is decorated as a tool (@mcp.tool(), @tool, ...) or it
    performs a sensitive action itself."""
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = dotted_name(target, aliases)
        if name is not None and "tool" in name_tokens(name):
            return True
    return next(iter_sensitive_calls(fn, aliases), None) is not None
