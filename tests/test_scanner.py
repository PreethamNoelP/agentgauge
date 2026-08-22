from pathlib import Path

import agentgauge.scanner as scanner_module
from agentgauge.astutils import FileContext
from agentgauge.config import Config, RuleConfig
from agentgauge.scanner import iter_python_files, scan


def test_scan_walks_directory_and_skips_junk_dirs(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "server.py").write_text(
        "def wipe(path):\n    shutil.rmtree(path)\n"
    )
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("auto_approve = True\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert any(f.file == "pkg/server.py" for f in report.findings)
    defaults_cat = next(
        c for c in report.categories if c.name == "Permissive defaults"
    )
    assert defaults_cat.sites == 0  # the .venv flag was never seen


def test_syntax_error_is_reported_not_fatal(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    (tmp_path / "good.py").write_text("x = 1\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert len(report.skipped) == 1
    assert "bad.py" in report.skipped[0]


def test_recursion_error_is_skipped_not_fatal(tmp_path, monkeypatch):
    # The nesting depth at which ast.parse overflows varies by platform and
    # Python version (Linux 3.13 parses chains that crash Windows 3.11), so
    # simulate the RecursionError instead of trying to provoke a real one --
    # the contract under test is the scanner's handling, not CPython's stack.
    (tmp_path / "deep.py").write_text("x = 1\n")
    (tmp_path / "good.py").write_text("auto_approve = True\n")

    class ExplodingFileContext:
        @staticmethod
        def from_source(source, path="<memory>", config=None):
            if path == "deep.py":
                raise RecursionError
            return FileContext.from_source(source, path=path, config=config)

    monkeypatch.setattr(scanner_module, "FileContext", ExplodingFileContext)

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert len(report.skipped) == 1
    assert "deep.py" in report.skipped[0]
    assert any(f.rule == "permissive-defaults" for f in report.findings)


def test_scan_accepts_a_single_file(tmp_path):
    target = tmp_path / "one.py"
    target.write_text("auto_approve = True\n")

    report = scan(target)

    assert report.files_scanned == 1
    assert report.findings[0].file == "one.py"
    assert report.score == 90.0  # only permissive-defaults loses its 10


def test_exclude_glob_skips_matching_files(tmp_path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "vulnerable.py").write_text("auto_approve = True\n")
    (tmp_path / "server.py").write_text("auto_approve = True\n")

    config = Config(exclude=("fixtures/*",))
    report = scan(tmp_path, config=config)

    assert report.files_scanned == 1
    assert report.findings[0].file == "server.py"


def test_iter_python_files_honors_exclude_patterns(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "generated_b.py").write_text("x = 1\n")

    paths = list(iter_python_files(tmp_path, exclude=("generated_*.py",)))

    assert [p.name for p in paths] == ["a.py"]


def test_scan_disables_rules_from_config(tmp_path):
    (tmp_path / "server.py").write_text(
        "@mcp.tool()\ndef fetch(url):\n    return http.get(url)\n"
    )
    config = Config(rules=RuleConfig(disabled_rules=frozenset({"rate-limiting"})))

    report = scan(tmp_path, config=config)

    assert "Rate limiting" not in {c.name for c in report.categories}
    assert report.max_score == 85


def test_scan_with_no_config_behaves_exactly_as_before(tmp_path):
    (tmp_path / "server.py").write_text("auto_approve = True\n")

    report = scan(tmp_path)

    assert report.max_score == 100
    assert report.suppressed == 0

# --- skip-dir matching must be relative to the scan root ---

def test_repo_living_under_a_skip_named_directory_is_still_scanned(tmp_path):
    # SKIP_DIRS used to be matched against every component of the absolute
    # path, so a checkout in ~/dev/build/ or C:\...\dist\ had every file
    # skipped and the scan exited "no Python files scanned".
    root = tmp_path / "build" / "myrepo"
    root.mkdir(parents=True)
    (root / "server.py").write_text("import shutil\ndef f(p):\n    shutil.rmtree(p)\n")

    report = scan(root)

    assert report.files_scanned == 1
    assert report.verdict == "FAIL_CRITICAL"


def test_skip_dirs_still_apply_inside_the_scan_root(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "generated.py").write_text("auto_approve = True\n")
    (tmp_path / "app.py").write_text("x = 1\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1


# --- exclude pattern semantics ---

def test_double_star_prefix_also_matches_at_the_root(tmp_path):
    # "**/generated_*.py" is how people write "at any depth", but fnmatch
    # reads "**/" as "characters then a literal slash", so this pattern
    # silently matched nothing in the repo root.
    (tmp_path / "generated_a.py").write_text("x = 1\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "generated_b.py").write_text("x = 1\n")
    (tmp_path / "pkg" / "real.py").write_text("x = 1\n")

    paths = list(iter_python_files(tmp_path, exclude=("**/generated_*.py",)))

    assert [p.name for p in paths] == ["real.py"]


def test_directory_pattern_excludes_everything_under_it(tmp_path):
    (tmp_path / "vendor" / "deep").mkdir(parents=True)
    (tmp_path / "vendor" / "deep" / "lib.py").write_text("x = 1\n")
    (tmp_path / "app.py").write_text("x = 1\n")

    for pattern in ("vendor", "vendor/"):
        paths = list(iter_python_files(tmp_path, exclude=(pattern,)))
        assert [p.name for p in paths] == ["app.py"], pattern


def test_slash_free_pattern_matches_the_basename_at_any_depth(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "thing.gen.py").write_text("x = 1\n")
    (tmp_path / "keep.py").write_text("x = 1\n")

    paths = list(iter_python_files(tmp_path, exclude=("*.gen.py",)))

    assert [p.name for p in paths] == ["keep.py"]


def test_exclude_matching_is_case_sensitive_on_every_platform(tmp_path):
    # fnmatch (not fnmatchcase) normalizes case via os.path.normcase, which
    # would make the same config exclude different files on Windows than on
    # Linux. A CI tool must not be platform-dependent here.
    (tmp_path / "Server.py").write_text("x = 1\n")

    paths = list(iter_python_files(tmp_path, exclude=("server.py",)))

    assert [p.name for p in paths] == ["Server.py"]


def test_explicit_single_file_target_ignores_exclude_patterns(tmp_path):
    target = tmp_path / "server.py"
    target.write_text("auto_approve = True\n")

    report = scan(target, config=Config(exclude=("*.py",)))

    assert report.files_scanned == 1


# --- hostile or unreadable sources are skipped, never fatal ---

def test_source_with_null_bytes_is_skipped(tmp_path):
    (tmp_path / "nul.py").write_bytes(b"x = 1\ny = '\x00'\n")
    (tmp_path / "ok.py").write_text("auto_approve = True\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert any("nul.py" in entry for entry in report.skipped)
    assert report.verdict == "INCOMPLETE"


def test_unknown_encoding_declaration_is_skipped(tmp_path):
    (tmp_path / "enc.py").write_bytes(b"# -*- coding: not-a-real-codec -*-\nx = 1\n")
    (tmp_path / "ok.py").write_text("x = 1\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert any("enc.py" in entry for entry in report.skipped)


def test_oversized_file_is_skipped_rather_than_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_module, "MAX_FILE_BYTES", 32)
    (tmp_path / "huge.py").write_text("x = 1\n" * 100)
    (tmp_path / "ok.py").write_text("x = 1\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert any("huge.py" in entry and "limit" in entry for entry in report.skipped)


# --- reported paths ---

def test_findings_are_reported_relative_to_the_working_directory(tmp_path, monkeypatch):
    # SARIF results and clickable terminal output both need a path that
    # resolves from where the tool was invoked. A root-relative path meant
    # `agentgauge src/` reported "server.py" for src/server.py.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.py").write_text("auto_approve = True\n")
    monkeypatch.chdir(tmp_path)

    report = scan(Path("src"))

    assert [f.file for f in report.findings] == ["src/server.py"]


def test_single_file_target_keeps_its_directory_in_the_reported_path(
    tmp_path, monkeypatch
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.py").write_text("auto_approve = True\n")
    monkeypatch.chdir(tmp_path)

    report = scan(Path("src/server.py"))

    assert report.findings[0].file == "src/server.py"


def test_target_outside_the_working_directory_falls_back_to_root_relative(
    tmp_path, monkeypatch
):
    other = tmp_path / "elsewhere"
    (other / "pkg").mkdir(parents=True)
    (other / "pkg" / "server.py").write_text("auto_approve = True\n")
    unrelated = tmp_path / "cwd"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)

    report = scan(other)

    assert report.findings[0].file == "pkg/server.py"
