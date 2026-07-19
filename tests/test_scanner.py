from agentgauge.scanner import scan


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


def test_too_deeply_nested_file_is_skipped_not_fatal(tmp_path):
    # 5000 chained unary operators blow the parser's recursion guard with a
    # RecursionError (unlike parentheses, which raise plain SyntaxError).
    (tmp_path / "deep.py").write_text("x = " + "not " * 5000 + "True\n")
    (tmp_path / "good.py").write_text("auto_approve = True\n")

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