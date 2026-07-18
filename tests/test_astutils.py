import ast

from agentgauge.astutils import (
    build_parent_map,
    call_name,
    enclosing_function,
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
