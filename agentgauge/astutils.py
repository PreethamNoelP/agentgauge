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
    "os.removedirs": "file delete",
    "os.truncate": "file delete",
    "shutil.rmtree": "file delete",
    # shell / process execution
    "os.system": "shell exec",
    "os.popen": "shell exec",
    "subprocess.run": "shell exec",
    "subprocess.call": "shell exec",
    "subprocess.check_call": "shell exec",
    "subprocess.check_output": "shell exec",
    "subprocess.Popen": "shell exec",
    "subprocess.getoutput": "shell exec",
    "subprocess.getstatusoutput": "shell exec",
    "os.execl": "shell exec",
    "os.execle": "shell exec",
    "os.execlp": "shell exec",
    "os.execv": "shell exec",
    "os.execve": "shell exec",
    "os.execvp": "shell exec",
    "os.execvpe": "shell exec",
    "os.posix_spawn": "shell exec",
    "os.posix_spawnp": "shell exec",
    "os.spawnl": "shell exec",
    "os.spawnv": "shell exec",
    "pty.spawn": "shell exec",
    # async process execution -- the asyncio equivalents of subprocess.*,
    # which an agent server written with async handlers is more likely to
    # use than the blocking API.
    "asyncio.create_subprocess_shell": "shell exec",
    "asyncio.create_subprocess_exec": "shell exec",
    # dynamic code execution
    "eval": "code exec",
    "exec": "code exec",
    # deserialization that is equivalent to code execution on untrusted
    # input -- the realistic shape being "agent output -> loads()". Only
    # APIs with no safe mode are listed: yaml.load is deliberately absent
    # (yaml.load(s, Loader=SafeLoader) is safe and far too common to flag),
    # while yaml.unsafe_load names its own risk.
    "pickle.load": "code exec",
    "pickle.loads": "code exec",
    "marshal.load": "code exec",
    "marshal.loads": "code exec",
    "dill.load": "code exec",
    "dill.loads": "code exec",
    "yaml.unsafe_load": "code exec",
    # state-changing HTTP
    "requests.delete": "remote delete",
    "httpx.delete": "remote delete",
}

# Bare method names distinctive enough to flag on ANY receiver
# (client.rmtree(...), gateway.charge(...)). Deliberately excludes generic
# names like "run", "call", "delete", "system" -- those would flag half of
# any normal repo.
SENSITIVE_SUFFIX: dict[str, str] = {
    "rmtree": "file delete",
    "unlink": "file delete",       # pathlib.Path.unlink -- the modern idiom
    "rmdir": "file delete",
    "removedirs": "file delete",
    "delete_file": "file delete",
    "remove_file": "file delete",
    "delete_directory": "file delete",
    "remove_directory": "file delete",
    "Popen": "shell exec",
    "check_output": "shell exec",
    "getoutput": "shell exec",
    "getstatusoutput": "shell exec",
    "create_subprocess_shell": "shell exec",
    "create_subprocess_exec": "shell exec",
    "unsafe_load": "code exec",
    # bulk/remote destruction: object stores, databases, cloud instances.
    # All distinctive multi-word names -- bare "delete"/"drop" stay out.
    "delete_object": "remote delete",
    "delete_objects": "remote delete",
    "delete_bucket": "remote delete",
    "delete_many": "remote delete",
    "delete_all": "remote delete",
    "destroy_all": "remote delete",
    "drop_table": "remote delete",
    "drop_database": "remote delete",
    "drop_collection": "remote delete",
    "truncate_table": "remote delete",
    "terminate_instances": "remote delete",
    "charge": "payment",
    "create_charge": "payment",
    "create_payment": "payment",
    "create_payment_intent": "payment",
    "send_payment": "payment",
    "send_money": "payment",
    "transfer_funds": "payment",
    "wire_transfer": "payment",
    "create_transfer": "payment",
    "capture_payment": "payment",
    "refund": "payment",
    "payout": "payment",
    "create_payout": "payment",
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
    if name is not None:
        if name in SENSITIVE_EXACT:
            return SENSITIVE_EXACT[name]
        return SENSITIVE_SUFFIX.get(name.rsplit(".", 1)[-1])
    # dotted_name gave up because the receiver is dynamic
    # (Path(p).unlink(), clients[key].charge()). The suffix table is
    # receiver-agnostic by construction -- the method name alone is the
    # whole signal -- so it still applies. The exact table does not: it
    # exists precisely to require a known module chain.
    if isinstance(call.func, ast.Attribute):
        return SENSITIVE_SUFFIX.get(call.func.attr)
    return None


def iter_sensitive_calls(tree: ast.AST, aliases: dict[str, str] | None = None):
    """Yield (call_node, action_label) for every sensitive call in the tree."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            label = sensitive_label(node, aliases)
            if label is not None:
                yield node, label


def build_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map every locally-bound import name to the dotted name it actually
    refers to, so a call written through an import binding resolves to its
    canonical target instead of vanishing behind the local spelling:

        import subprocess as sp   ->  {"sp": "subprocess"}
        from shutil import rmtree ->  {"rmtree": "shutil.rmtree"}
        from os import system as s ->  {"s": "os.system"}

    `from X import y` matters as much as the `as` form: `from subprocess
    import run; run(cmd, shell=True)` resolves to nothing but the bare name
    "run", which the suffix table deliberately excludes as too generic --
    so without this mapping that call was invisible entirely.

    A plain `import os.path` needs no entry: it binds "os", and dotted_name
    already walks the Attribute chain from there. Relative imports
    (`from . import x`) are skipped -- their target isn't a static dotted
    name we could resolve to.

    Scope-blind by design: this is one flat map per file, so a local
    variable that shadows an imported name still resolves to the import
    (documented in RULES.md).
    """
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
                if alias.name == "*":
                    continue
                local = alias.asname if alias.asname is not None else alias.name
                aliases[local] = f"{node.module}.{alias.name}"
    return aliases


def iter_scope(scope: ast.AST):
    """Yield `scope` and every descendant that executes in the *same* scope.

    Nested def/async def bodies are separate scopes and are not entered: a
    check written inside a helper function does not run when the code around
    that helper does. This is what makes "is there an approval check in
    scope?" answerable without confusing a call at module level with an
    unrelated function that happens to live in the same file.

    Class bodies *are* entered -- `class C: os.system(x)` executes at
    definition time in the surrounding scope, so its statements belong to it.
    Lambdas are entered too: a lambda body is an expression evaluated where
    it is written.
    """
    yield scope
    queue = list(ast.iter_child_nodes(scope))
    while queue:
        node = queue.pop(0)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        yield node
        queue.extend(ast.iter_child_nodes(node))


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
#
# The bracket group captures anything up to "]" rather than only well-formed
# rule ids on purpose. An earlier pattern accepted only [\w, -]+ inside the
# brackets, which meant "ignore[]" and "ignore[typo!]" failed to match the
# bracketed alternative, fell back to the bare "ignore" alternative, and
# silently escalated a narrow (or empty) suppression into a blanket one.
# Matching greedily and validating afterwards keeps a malformed marker
# malformed. \b stops "ignored"/"ignoring" in prose from suppressing.
_SUPPRESS_RE = re.compile(
    r"#\s*agentgauge:\s*ignore\b[ \t]*(\[[^\]]*\])?", re.IGNORECASE
)

# Rule ids are lowercase kebab-case ("human-oversight"). Anything else in a
# suppression list is a typo, not a rule we might not know about yet.
_RULE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


def _parse_suppressions(
    source: str,
) -> tuple[dict[int, frozenset[str] | None], list[tuple[int, str]]]:
    """Scan comment tokens (not a text search -- a string literal that
    happens to contain the marker must not count) for suppression markers.

    Returns (suppressions, malformed):
      - suppressions maps line number -> None (suppress everything on that
        line) or a frozenset of rule ids (suppress only those).
      - malformed lists (line, reason) for markers that could not be parsed.
        A malformed marker suppresses *nothing*: a suppression is a security
        decision, and the safe reading of one we cannot understand is that
        no exemption was granted. The reason is surfaced as a scan warning so
        a typo does not just sit there silently failing to do its job.

    Best-effort: a source that parses with ast.parse but somehow fails to
    tokenize just gets no suppressions rather than aborting the scan.
    """
    suppressions: dict[int, frozenset[str] | None] = {}
    malformed: list[tuple[int, str]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type != tokenize.COMMENT:
                continue
            match = _SUPPRESS_RE.search(tok.string)
            if match is None:
                continue
            line = tok.start[0]
            brackets = match.group(1)
            if brackets is None:
                suppressions[line] = None
                continue
            rules = [r.strip().lower() for r in brackets[1:-1].split(",")]
            rules = [r for r in rules if r]
            if not rules:
                malformed.append((line, "empty rule list in 'ignore[]'"))
            elif any(not _RULE_ID_RE.match(r) for r in rules):
                bad = next(r for r in rules if not _RULE_ID_RE.match(r))
                malformed.append((line, f"'{bad}' is not a valid rule id"))
            else:
                suppressions[line] = frozenset(rules)
    except (tokenize.TokenError, SyntaxError, IndentationError):
        pass
    return suppressions, malformed


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
    # (line, reason) for suppression comments that could not be parsed; they
    # grant no exemption and are reported as warnings by the scoring pass.
    malformed_suppressions: list[tuple[int, str]] = field(default_factory=list)

    @classmethod
    def from_source(
        cls,
        source: str,
        path: str = "<memory>",
        config: RuleConfig | None = None,
    ) -> "FileContext":
        tree = ast.parse(source)
        suppressions, malformed = _parse_suppressions(source)
        return cls(
            path=path,
            tree=tree,
            parents=build_parent_map(tree),
            import_aliases=build_import_aliases(tree),
            config=config if config is not None else RuleConfig(),
            suppressions=suppressions,
            malformed_suppressions=malformed,
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
