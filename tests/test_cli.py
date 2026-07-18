import json

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


def test_json_output_is_parseable(tmp_path, capsys):
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path), "--json"])

    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["score"] == 90.0
    assert data["findings"][0]["rule"] == "permissive-defaults"


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
