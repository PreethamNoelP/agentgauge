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