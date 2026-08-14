import json

import pytest

from agentgauge.cli import main


def test_clean_scan_prints_score_and_exits_zero(tmp_path, capsys):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")

    code = main([str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "100.0 / 100" in out


def test_min_score_gate_returns_one(tmp_path, capsys):
    (tmp_path / "bad.py").write_text(
        "def wipe(path):\n    shutil.rmtree(path)\n"
    )

    code = main([str(tmp_path), "--min-score", "70"])

    assert code == 1
    assert "fix:" in capsys.readouterr().out  # findings still printed


def test_critical_finding_returns_one_even_without_min_score(tmp_path, capsys):
    # A live, unguarded critical action must fail the build on its own --
    # no --min-score needed to catch it (issue #1).
    (tmp_path / "bad.py").write_text(
        "def wipe(path):\n    shutil.rmtree(path)\n"
    )

    code = main([str(tmp_path)])

    assert code == 1
    assert "FAIL_CRITICAL" in capsys.readouterr().out


def test_critical_finding_returns_one_even_above_min_score(tmp_path, capsys):
    # A permissive --min-score must not buy back a pass on a critical
    # finding just because the aggregate score clears the bar.
    (tmp_path / "bad.py").write_text(
        "def wipe(path):\n    shutil.rmtree(path)\n"
    )

    code = main([str(tmp_path), "--min-score", "1"])

    assert code == 1


def test_json_output_is_parseable(tmp_path, capsys):
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path), "--json"])

    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["score"] == 90.0
    assert data["verdict"] == "PASS"
    assert data["findings"][0]["rule"] == "permissive-defaults"
    assert data["findings"][0]["critical"] is False


def test_missing_target_returns_two(capsys):
    code = main(["definitely_not_a_real_path_xyz"])

    assert code == 2
    assert "not found" in capsys.readouterr().err


def test_directory_with_no_python_files_returns_two(tmp_path, capsys):
    # A pure-JS MCP server must not get a green 100/100 from a scanner
    # that looked at nothing.
    (tmp_path / "server.js").write_text("// not python\n")

    code = main([str(tmp_path)])

    assert code == 2
    assert "no Python files" in capsys.readouterr().err


def test_all_files_unparseable_returns_two(tmp_path, capsys):
    (tmp_path / "broken.py").write_text("def broken(:\n")

    code = main([str(tmp_path)])

    err = capsys.readouterr().err
    assert code == 2
    assert "skipped" in err
    assert "no Python files" in err


def test_sarif_output_is_parseable(tmp_path, capsys):
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path), "--sarif"])

    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "permissive-defaults"


def test_json_and_sarif_are_mutually_exclusive(tmp_path, capsys):
    # argparse itself rejects the combination before main() gets to run --
    # it exits via SystemExit(2), the same as any other malformed invocation.
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    with pytest.raises(SystemExit) as exc_info:
        main([str(tmp_path), "--json", "--sarif"])

    assert exc_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_min_score_from_config_file_gates_without_a_cli_flag(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.agentgauge]\nmin_score = 95\n")
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path)])

    assert code == 1  # 90.0 scored, below the config's min_score of 95


def test_cli_min_score_flag_overrides_config_file(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.agentgauge]\nmin_score = 95\n")
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path), "--min-score", "50"])

    assert code == 0  # CLI flag (50) wins over the config file's 95


def test_explicit_config_flag_is_used_instead_of_discovery(tmp_path, capsys):
    (tmp_path / "flags.py").write_text("auto_approve = True\n")
    custom = tmp_path / "custom.toml"
    custom.write_text("[tool.agentgauge]\nmin_score = 50\n")

    code = main([str(tmp_path), "--config", str(custom)])

    assert code == 0


def test_malformed_config_file_returns_two(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.agentgauge\nmin_score = 1\n")
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path)])

    assert code == 2
    assert "pyproject.toml" in capsys.readouterr().err


def test_inline_suppression_is_reflected_in_output(tmp_path, capsys):
    (tmp_path / "flags.py").write_text(
        "auto_approve = True  # agentgauge: ignore\n"
    )

    code = main([str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "100.0 / 100" in out
    assert "1 finding(s) suppressed" in out
