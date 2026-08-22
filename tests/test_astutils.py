import ast

from agentgauge.astutils import (
    FileContext,
    build_import_aliases,
    build_parent_map,
    call_name,
    dotted_name,
    enclosing_function,
    is_critical,
    iter_scope,
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


def test_build_import_aliases_maps_plain_from_import():
    # `from subprocess import run` binds the bare name "run", which the
    # suffix table excludes as too generic -- without this entry the call
    # `run(cmd, shell=True)` resolved to nothing at all.
    tree = ast.parse("from subprocess import run\n")
    assert build_import_aliases(tree) == {"run": "subprocess.run"}


def test_build_import_aliases_ignores_plain_module_import():
    # `import os.path` binds "os"; dotted_name already walks the Attribute
    # chain from there, so no entry is needed.
    tree = ast.parse("import os.path\n")
    assert build_import_aliases(tree) == {}


def test_build_import_aliases_skips_star_import():
    # `from subprocess import *` binds names we cannot enumerate statically.
    tree = ast.parse("from subprocess import *\n")
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


# --- vocabulary coverage for sinks that the first tables missed ---

def test_pathlib_unlink_is_a_file_delete_sink():
    # Path(p).unlink() is the modern deletion idiom; a table that only knew
    # os.remove/shutil.rmtree scored such code a clean 100.
    assert sensitive_label(first_call("target.unlink()")) == "file delete"


def test_async_subprocess_is_a_shell_exec_sink():
    src = "asyncio.create_subprocess_shell(cmd)"
    assert sensitive_label(first_call(src)) == "shell exec"


def test_async_subprocess_on_any_receiver_is_a_shell_exec_sink():
    assert sensitive_label(first_call("loop.create_subprocess_exec(*argv)")) == "shell exec"


def test_subprocess_getoutput_is_a_shell_exec_sink():
    assert sensitive_label(first_call("subprocess.getoutput(cmd)")) == "shell exec"


def test_pickle_loads_is_a_code_exec_sink():
    assert sensitive_label(first_call("pickle.loads(blob)")) == "code exec"


def test_yaml_load_is_not_flagged_but_unsafe_load_is():
    # yaml.load(s, Loader=SafeLoader) is safe and ubiquitous -- flagging it
    # would make the critical gate untrustworthy. yaml.unsafe_load names
    # its own risk, so it is fair game.
    assert sensitive_label(first_call("yaml.load(text, Loader=SafeLoader)")) is None
    assert sensitive_label(first_call("yaml.unsafe_load(text)")) == "code exec"


def test_bulk_remote_deletion_is_a_sink():
    assert sensitive_label(first_call("s3.delete_bucket(Bucket=b)")) == "remote delete"
    assert sensitive_label(first_call("col.delete_many(query)")) == "remote delete"


def test_stripe_style_payment_calls_are_sinks():
    src = "stripe.PaymentIntent.create_payment_intent(amount=n)"
    assert sensitive_label(first_call(src)) == "payment"


def test_generic_delete_is_still_not_flagged():
    # The suffix table must stay distinctive: a cache eviction or a list
    # removal is not a governance event.
    assert sensitive_label(first_call("cache.delete(key)")) is None
    assert sensitive_label(first_call("items.remove(x)")) is None


def test_sensitive_label_sees_through_plain_from_import():
    # from os import system; system(cmd) -- the bare name "system" is
    # deliberately absent from the suffix table (platform.system and
    # friends), so only alias resolution can catch this shape.
    tree = ast.parse("from os import system\nsystem(cmd)\n")
    aliases = build_import_aliases(tree)
    assert [label for _, label in iter_sensitive_calls(tree, aliases)] == ["shell exec"]


def test_plain_from_import_of_subprocess_run_is_detected():
    tree = ast.parse("from subprocess import run\nrun(cmd, shell=True)\n")
    aliases = build_import_aliases(tree)
    assert [label for _, label in iter_sensitive_calls(tree, aliases)] == ["shell exec"]


def test_suffix_table_matches_through_a_dynamic_receiver():
    # dotted_name gives up on Path(p).unlink -- the receiver is a call
    # result, not a name chain. The suffix table is receiver-agnostic by
    # construction, so the attribute name alone must still be honored.
    assert sensitive_label(first_call("Path(p).unlink()")) == "file delete"
    assert sensitive_label(first_call("clients[k].charge(n)")) == "payment"


def test_dynamic_receiver_fallback_stays_suffix_only():
    # The fallback must not promote a generic method name; only the
    # distinctive suffix table applies.
    assert sensitive_label(first_call("get_db().delete(row)")) is None


# --- scope boundaries ---

def test_iter_scope_does_not_enter_nested_functions():
    tree = ast.parse(
        "x = 1\n"
        "def helper():\n"
        "    y = 2\n"
        "class C:\n"
        "    z = 3\n"
    )
    names = {n.id for n in iter_scope(tree) if isinstance(n, ast.Name)}
    assert names == {"x", "z"}  # y lives in helper's own scope


def test_iter_scope_of_a_function_yields_the_function_itself():
    fn = ast.parse("def f():\n    pass\n").body[0]
    assert next(iter_scope(fn)) is fn
