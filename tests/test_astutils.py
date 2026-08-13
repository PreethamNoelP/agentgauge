import ast

from agentgauge.astutils import (
    FileContext,
    build_import_aliases,
    build_parent_map,
    call_name,
    dotted_name,
    enclosing_function,
    is_critical,
    iter_sensitive_calls,
    sensitive_label,
)


def first_call(src: str) -> ast.Call:
    """Test helper: parse a snippet and return its first Call node."""
    tree = ast.parse(src)
    return next(n for n in ast.walk(tree) if isinstance(n, ast.Call))


# --- what is being called? ---

def test_call_name_resolves_dotted_chain():
    assert call_name(first_call("os.path.join(a, b)")) == "os.path.join"


def test_call_name_resolves_bare_name():
    assert call_name(first_call("eval(payload)")) == "eval"


def test_call_name_is_none_for_dynamic_call():
    # funcs["rm"](x): the thing being called is a subscript, not a name.
    # A static scan cannot know the target, so we must get None, not a crash.
    assert call_name(first_call('funcs["rm"](x)')) is None


# --- is it sensitive? ---

def test_exact_sensitive_match():
    assert sensitive_label(first_call("subprocess.run(cmd, shell=True)")) == "shell exec"


def test_suffix_sensitive_match_on_any_receiver():
    assert sensitive_label(first_call("client.charge(amount)")) == "payment"


def test_platform_system_is_not_flagged():
    # os.system is sensitive; platform.system is harmless. This pins down
    # that we exact-match "os.system" instead of suffix-matching "system".
    assert sensitive_label(first_call("platform.system()")) is None


def test_iter_sensitive_calls_finds_all_and_only_sensitive():
    src = "shutil.rmtree(tmp)\nprint('hi')\ngateway.charge(9)\n"
    labels = sorted(label for _, label in iter_sensitive_calls(ast.parse(src)))
    assert labels == ["file delete", "payment"]


# --- is it a critical-consequence sink? ---

def test_every_sensitive_label_is_critical():
    # Today's sensitive-call vocabulary is entirely made of the five
    # catastrophic consequence categories -- there is no low-risk sink yet.
    labels = {"file delete", "shell exec", "code exec", "payment", "remote delete"}
    assert all(is_critical(label) for label in labels)


def test_unknown_label_is_not_critical():
    assert is_critical("some future low-risk label") is False


# --- what surrounds a node? ---

def test_enclosing_function_finds_nearest_def():
    src = (
        "def outer():\n"
        "    def inner():\n"
        "        os.remove(path)\n"
    )
    tree = ast.parse(src)
    parents = build_parent_map(tree)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    fn = enclosing_function(call, parents)
    assert fn is not None
    assert fn.name == "inner"  # nearest def, not the outermost


def test_enclosing_function_none_at_module_level():
    tree = ast.parse("os.remove(path)")
    parents = build_parent_map(tree)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert enclosing_function(call, parents) is None


# --- import aliasing ---

def test_build_import_aliases_maps_module_asname():
    tree = ast.parse("import subprocess as sp\n")
    assert build_import_aliases(tree) == {"sp": "subprocess"}


def test_build_import_aliases_maps_from_import_asname():
    tree = ast.parse("from shutil import rmtree as rt\n")
    assert build_import_aliases(tree) == {"rt": "shutil.rmtree"}


def test_build_import_aliases_ignores_unaliased_imports():
    # `import os.path` and `from shutil import rmtree` need no alias entry:
    # dotted_name already walks the plain Attribute chain / bare Name.
    tree = ast.parse("import os.path\nfrom shutil import rmtree\n")
    assert build_import_aliases(tree) == {}


def test_build_import_aliases_skips_relative_imports():
    tree = ast.parse("from . import helper as h\n")
    assert build_import_aliases(tree) == {}


def test_dotted_name_resolves_module_alias():
    aliases = {"sp": "subprocess"}
    assert dotted_name(first_call("sp.run(cmd)").func, aliases) == "subprocess.run"


def test_dotted_name_resolves_bare_name_alias():
    aliases = {"rt": "shutil.rmtree"}
    assert dotted_name(first_call("rt(path)").func, aliases) == "shutil.rmtree"


def test_dotted_name_without_aliases_is_unchanged():
    # Default (no aliases arg) behaves exactly as before this feature existed.
    assert dotted_name(first_call("sp.run(cmd)").func) == "sp.run"


def test_sensitive_label_sees_through_module_import_alias():
    # The documented blind spot in RULES.md: `import subprocess as sp; sp.run(...)`.
    aliases = {"sp": "subprocess"}
    assert sensitive_label(first_call("sp.run(cmd, shell=True)"), aliases) == "shell exec"


def test_sensitive_label_sees_through_from_import_alias():
    aliases = {"rt": "shutil.rmtree"}
    assert sensitive_label(first_call("rt(path)"), aliases) == "file delete"


def test_iter_sensitive_calls_accepts_aliases():
    src = "import subprocess as sp\nsp.run(cmd)\n"
    tree = ast.parse(src)
    aliases = build_import_aliases(tree)
    labels = [label for _, label in iter_sensitive_calls(tree, aliases)]
    assert labels == ["shell exec"]


# --- inline suppression comments ---

def test_is_suppressed_for_unqualified_ignore_comment():
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # agentgauge: ignore\n", path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 1) is True
    assert ctx.is_suppressed("error-handling", 1) is True


def test_is_suppressed_for_rule_scoped_ignore_comment():
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # agentgauge: ignore[human-oversight]\n", path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 1) is True
    assert ctx.is_suppressed("error-handling", 1) is False


def test_is_suppressed_for_multiple_rule_scoped_ignore_comment():
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # agentgauge: ignore[human-oversight, error-handling]\n",
        path="mem.py",
    )
    assert ctx.is_suppressed("human-oversight", 1) is True
    assert ctx.is_suppressed("error-handling", 1) is True
    assert ctx.is_suppressed("audit-logging", 1) is False


def test_is_suppressed_is_false_for_unmarked_lines():
    ctx = FileContext.from_source("shutil.rmtree(path)\n", path="mem.py")
    assert ctx.is_suppressed("human-oversight", 1) is False


def test_suppression_marker_in_a_string_literal_is_not_a_comment():
    # Only real COMMENT tokens count -- a string that happens to contain the
    # marker text must not accidentally suppress anything.
    ctx = FileContext.from_source(
        'msg = "# agentgauge: ignore"\nshutil.rmtree(path)\n', path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 2) is False
