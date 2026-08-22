"""Invariants that must hold for every rule on every input.

The per-rule tests check that a rule gets specific cases right. These check
the properties the scoring model *relies* on -- if a rule breaks one of
them, every score it contributes to is quietly wrong rather than visibly
broken. They also serve as a crash corpus: a governance scanner is pointed
at untrusted repositories, so "does not raise" is a real requirement.
"""

import ast
import json
from pathlib import Path

import pytest

from agentgauge.astutils import FileContext
from agentgauge.config import Config, RuleConfig
from agentgauge.sarif import build_sarif
from agentgauge.scanner import scan
from agentgauge.scoring import ALL_RULES, score_contexts

FIXTURES = Path(__file__).parent / "fixtures"

# Awkward Python that a rule could plausibly trip over. Every entry must
# parse -- the scanner's handling of *un*parseable input is tested in
# test_scanner.py.
CORPUS = [
    "",
    "\n\n\n",
    "'''just a docstring'''",
    "x = 1",
    # empty and unusual definitions
    "def f(): ...",
    "async def f(): ...",
    "class C: ...",
    "class C:\n    class D:\n        def m(self): ...",
    "def f(a=1, /, *, b=2): ...",
    "def f(a, /, b, *args, c=1, **kw): ...",
    "lambda: os.remove(p)",
    # decorators of every shape
    "@a\n@b.c\n@d.e(f=1)\n@g[0]\ndef h(): ...",
    "@(lambda f: f)\ndef h(): ...",
    # comprehensions, walrus, match, starred, f-strings
    "[os.remove(p) for p in ps]",
    "{k: shutil.rmtree(k) for k in ks}",
    "if (n := len(xs)) > 1: os.system('x')",
    "match cmd:\n    case ['rm', p]: os.remove(p)\n    case _: pass",
    "f'{os.system(cmd)}'",
    "print(*[eval(x) for x in xs])",
    # try/except* and nested handlers
    "try:\n    os.remove(p)\nexcept* OSError:\n    pass",
    "try:\n    pass\nexcept OSError:\n    os.remove(p)\nelse:\n    eval(x)\nfinally:\n    exec(y)",
    # loops
    "while True: pass",
    "while 1:\n    for x in y:\n        break",
    "while True:\n    async def inner():\n        return 1",
    "async def f():\n    async with lock:\n        await client.charge(1)",
    "async def f():\n    async for x in y:\n        os.remove(x)",
    # imports of every shape
    "from . import x",
    "from .. import y as z",
    "from a import *",
    "import a.b.c as d",
    "from a import (b as c, d)",
    # suppression comments, valid and not
    "os.remove(p)  # agentgauge: ignore",
    "os.remove(p)  # agentgauge: ignore[]",
    "os.remove(p)  # agentgauge: ignore[human-oversight]",
    "os.remove(p)  # agentgauge: ignore[not a rule!]",
    "os.remove(p)  # AGENTGAUGE: IGNORE[HUMAN-OVERSIGHT]",
    "#!/usr/bin/env python\n# -*- coding: utf-8 -*-\nos.remove(p)",
    # flags in awkward positions
    "d = {'auto_approve': True, **rest}",
    "f(verify=False, **kw)",
    "obj.attr.auto_approve = True",
    "x: bool = True",
    "auto_approve: bool = True",
    # unicode identifiers and deep chains
    "def función(ruta): os.remove(ruta)",
    "a.b.c.d.e.f.g.h.charge(1)",
    "((((os)))).remove(p)",
]

CONFIGS = [
    RuleConfig(),
    RuleConfig(assume_external_rate_limiting=True),
    RuleConfig(approval_markers=("vet",), log_tokens=frozenset({"telemetry"})),
    RuleConfig(disabled_rules=frozenset({"rate-limiting"})),
]


def contexts(config: RuleConfig):
    for src in CORPUS:
        yield FileContext.from_source(src, path="mem.py", config=config)


@pytest.mark.parametrize("src", CORPUS)
@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.RULE_ID)
def test_every_site_is_either_passed_or_reported(rule, src):
    """sites == passed + len(findings).

    Scoring derives points from passed/sites and treats findings as the
    explanation. A rule that counts a site it neither passes nor reports
    silently lowers a score with nothing to show the user; one that reports
    more than it counted can push a category above its weight.
    """
    ctx = FileContext.from_source(src, path="mem.py")
    sites, passed, findings = rule.check(ctx)

    assert sites >= 0 and passed >= 0
    assert passed <= sites
    assert sites == passed + len(findings)


@pytest.mark.parametrize("src", CORPUS)
@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.RULE_ID)
def test_findings_are_locatable_and_actionable(rule, src):
    ctx = FileContext.from_source(src, path="mem.py")
    _, _, findings = rule.check(ctx)
    line_count = len(src.splitlines()) or 1

    for f in findings:
        assert f.rule == rule.RULE_ID
        assert f.file == "mem.py"
        assert 1 <= f.line <= line_count, (f.line, line_count)
        assert f.message and f.fix  # what is wrong, and what to do
        assert isinstance(f.critical, bool)


@pytest.mark.parametrize("config", CONFIGS, ids=range(len(CONFIGS)))
def test_score_stays_within_bounds(config):
    report = score_contexts(
        contexts(config), disabled_rules=config.disabled_rules
    )
    assert 0.0 <= report.score <= report.max_score
    for c in report.categories:
        assert 0.0 <= c.score <= c.weight


def test_the_whole_corpus_scans_without_raising():
    report = score_contexts(contexts(RuleConfig()))
    assert report.files_scanned == len(CORPUS)
    json.dumps(report.to_dict())  # the report must also be serializable
    json.dumps(build_sarif(report))


@pytest.mark.parametrize("src", CORPUS)
def test_cached_context_views_never_disagree_with_the_tree(src):
    ctx = FileContext.from_source(src, path="mem.py")
    all_functions = {
        n for n in ast.walk(ctx.tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert set(ctx.functions) == all_functions
    assert ctx.tool_functions <= all_functions


# --- determinism: two runs of the same commit must be byte-identical ---

def test_scanning_the_same_tree_twice_gives_identical_json(tmp_path):
    for i, src in enumerate(CORPUS):
        (tmp_path / f"m{i:02d}.py").write_text(src)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "server.py").write_text(
        "import shutil\ndef wipe(p):\n    shutil.rmtree(p)\n"
    )

    first = json.dumps(scan(tmp_path).to_dict(), indent=2)
    second = json.dumps(scan(tmp_path).to_dict(), indent=2)

    assert first == second


def test_fixture_scan_is_deterministic():
    first = json.dumps(scan(FIXTURES).to_dict(), sort_keys=True)
    second = json.dumps(scan(FIXTURES).to_dict(), sort_keys=True)
    assert first == second


# --- the JSON contract consumers build against ---

def test_json_report_top_level_keys_are_stable():
    # Consumers parse this. Adding a key is backward compatible; removing
    # or renaming one is not, and should fail here first.
    report = scan(FIXTURES / "vulnerable_server.py")

    assert set(report.to_dict()) == {
        "score",
        "max_score",
        "verdict",
        "files_scanned",
        "total_sites",
        "critical_gate_active",
        "categories",
        "findings",
        "skipped",
        "suppressed",
        "critical_suppressed",
        "warnings",
    }


def test_json_finding_keys_are_stable():
    report = scan(FIXTURES / "vulnerable_server.py")
    finding = report.to_dict()["findings"][0]

    assert set(finding) == {"rule", "file", "line", "message", "fix", "critical"}


def test_verdict_is_always_one_of_three_values(tmp_path):
    (tmp_path / "a.py").write_text("import shutil\ndef f(p):\n    shutil.rmtree(p)\n")
    (tmp_path / "b.py").write_text("def broken(:\n")
    (tmp_path / "c.py").write_text("auto_approve = False\n")

    for config in (Config(), Config(exclude=("a.py",))):
        assert scan(tmp_path, config=config).verdict in {
            "PASS", "FAIL_CRITICAL", "INCOMPLETE"
        }


# --- suppression can never improve the verdict on a critical sink ---

@pytest.mark.parametrize(
    "marker",
    [
        "# agentgauge: ignore",
        "# agentgauge: ignore[human-oversight]",
        "# agentgauge: ignore[human-oversight, error-handling]",
        "# AGENTGAUGE: IGNORE",
    ],
)
def test_no_suppression_can_turn_a_critical_sink_into_a_pass(marker):
    ctx = FileContext.from_source(
        f"import shutil\ndef wipe(p):\n    shutil.rmtree(p)  {marker}\n",
        path="mem.py",
    )
    report = score_contexts([ctx])

    assert report.verdict == "FAIL_CRITICAL"
    assert report.critical_suppressed >= 1


# --- the "nothing leaves your machine" promise, enforced ---

# README.md and SECURITY.md both state this exact list. A scanner people run
# on proprietary code has to be able to back that claim up, and a promise in
# a markdown file is not a guarantee -- this test is.
ALLOWED_STDLIB_IMPORTS = {
    "argparse", "ast", "dataclasses", "fnmatch", "functools", "io", "json",
    "os", "pathlib", "re", "sys", "tokenize", "tomllib", "typing",
}

PACKAGE = Path(__file__).parent.parent / "agentgauge"


def _package_imports() -> set[str]:
    found = set()
    for source in sorted(PACKAGE.rglob("*.py")):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                found.add(node.module.split(".")[0])
    return found - {"agentgauge"}


def test_package_imports_nothing_outside_the_documented_stdlib_set():
    unexpected = _package_imports() - ALLOWED_STDLIB_IMPORTS
    assert not unexpected, (
        f"new import(s) {sorted(unexpected)} in the shipped package. If this is "
        "intentional, update ALLOWED_STDLIB_IMPORTS *and* the import lists in "
        "README.md and SECURITY.md -- and make sure the new module cannot open "
        "a socket, or the 'nothing leaves your machine' claim becomes false."
    )


def test_documented_import_list_is_not_stale():
    # The other direction: a module dropped from the package should be
    # dropped from the docs too, or the claim overstates what is there.
    assert _package_imports() == ALLOWED_STDLIB_IMPORTS


def test_package_has_no_runtime_dependencies():
    text = (PACKAGE.parent / "pyproject.toml").read_text(encoding="utf-8")
    # Only the [project.optional-dependencies] dev extra may list anything.
    assert "\ndependencies = [" not in text


def test_package_never_opens_a_file_for_writing():
    # Every open() in the package must be a read, or os.devnull. A scan must
    # leave the filesystem exactly as it found it.
    for source in sorted(PACKAGE.rglob("*.py")):
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(
                func, "id", ""
            )
            if name != "open":
                continue
            modes = [
                a.value for a in node.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str)
            ]
            writes = [m for m in modes if set("wax+") & set(m)]
            devnull = any(
                isinstance(a, ast.Attribute) and a.attr == "devnull"
                for a in node.args
            )
            assert not writes or devnull, (
                f"{source.name}:{node.lineno} opens a file for writing ({modes})"
            )
