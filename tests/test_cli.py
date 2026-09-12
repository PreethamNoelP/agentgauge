import json

import pytest

from agentgauge import __version__
from agentgauge import cli
from agentgauge.cli import _print_report, main
from agentgauge.models import CategoryResult, Finding
from agentgauge.scoring import ScanReport


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
    # no --min-score needed to catch it (critical-site dilution).
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


def test_version_flag_prints_the_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_fail_on_incomplete_turns_a_partial_scan_red(tmp_path, capsys):
    # A file agentgauge could not parse is a hole in its coverage; a repo
    # that wants CI to reflect that can now say so.
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "broken.py").write_text("def broken(:\n")

    assert main([str(tmp_path)]) == 0
    assert main([str(tmp_path), "--fail-on-incomplete"]) == 1
    assert "INCOMPLETE" in capsys.readouterr().out


def test_fail_on_incomplete_does_not_affect_a_complete_scan(tmp_path):
    (tmp_path / "ok.py").write_text("auto_approve = False\n")

    assert main([str(tmp_path), "--fail-on-incomplete"]) == 0


def test_zero_sites_cannot_pass_the_strictest_gate(tmp_path, capsys):
    # The hole: a repo agentgauge recognized nothing in scored 100.0/100
    # and exited 0 under `--min-score 100 --fail-on-incomplete` -- the
    # strictest invocation available. A team reading that green build
    # concluded "governed" when the truthful answer was "not measured".
    (tmp_path / "util.py").write_text("def add(a, b):\n    return a + b\n")

    code = main([str(tmp_path), "--min-score", "100", "--fail-on-incomplete"])

    captured = capsys.readouterr()
    assert code == 1
    assert "INCOMPLETE" in captured.out
    assert "APPLICABLE SITES" in captured.out
    assert "absence of anything to check" in captured.err


def test_excluded_file_count_is_shown_to_the_reader(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.agentgauge]\nexclude = ['hidden/*']\n"
    )
    (tmp_path / "hidden").mkdir()
    (tmp_path / "hidden" / "server.py").write_text("auto_approve = True\n")
    (tmp_path / "kept.py").write_text("auto_approve = False\n")

    main([str(tmp_path)])

    captured = capsys.readouterr()
    assert "EXCLUDED BY CONFIG" in captured.out
    assert "1 file(s)" in captured.out


def test_disabled_gate_rule_is_warned_about_and_not_a_pass(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.agentgauge]\ndisabled_rules = ['human-oversight']\n"
    )
    (tmp_path / "server.py").write_text(
        "import shutil\ndef wipe(path):\n    shutil.rmtree(path)\n"
    )

    code = main([str(tmp_path), "--fail-on-incomplete"])

    captured = capsys.readouterr()
    assert code == 1
    assert "INCOMPLETE" in captured.out
    assert "FAIL_CRITICAL gate" in captured.err


def test_config_source_is_reported_so_an_ignored_config_is_visible(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.agentgauge]\nmin_score = 1\n")
    (tmp_path / "server.py").write_text("x = 1\n")

    main([str(tmp_path)])

    assert "config: " in capsys.readouterr().out


def test_no_config_source_line_when_no_config_applies(tmp_path, capsys):
    (tmp_path / "server.py").write_text("x = 1\n")

    main([str(tmp_path)])

    assert "config: " not in capsys.readouterr().out


def test_json_output_carries_the_config_source(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.agentgauge]\nmin_score = 1\n")
    (tmp_path / "server.py").write_text("x = 1\n")

    main([str(tmp_path), "--json"])

    data = json.loads(capsys.readouterr().out)
    assert data["config_source"].endswith("pyproject.toml")


def test_control_characters_in_output_are_defanged(capsys):
    # File names are attacker-controlled on a scanned repo (a newline or an
    # ANSI escape is a legal POSIX filename), and they reach the terminal
    # verbatim. A path must not be able to repaint the report around it.
    escape = chr(27)
    report = ScanReport(categories=[], files_scanned=1)
    report.categories.append(
        CategoryResult(
            name="Permissive defaults",
            weight=10,
            sites=1,
            findings=[
                Finding(
                    rule="permissive-defaults",
                    file=f"evil{escape}[2Jname.py",
                    line=1,
                    message="permissive default",
                    fix="flip it",
                )
            ],
        )
    )

    _print_report(report, f"target{escape}[2J", None)

    out = capsys.readouterr().out
    assert escape not in out
    assert "\\x1b[2Jname.py" in out


def test_bidi_and_c1_characters_in_output_are_defanged(capsys):
    # Before: only C0 controls and DEL were escaped, so three ways of
    # misleading the reader survived. U+202E RIGHT-TO-LEFT OVERRIDE in a
    # file name reverses the rest of the line as it renders, which is the
    # Trojan Source trick (CVE-2021-42574) aimed at the report rather than
    # at source; 0x9B is CSI to a terminal in 8-bit mode, reaching the same
    # capability the C0 range already blocked through a different encoding;
    # and zero-width characters hide content outright. All are legal in a
    # POSIX filename, so all are attacker-controlled on a scanned repo.
    rlo, csi, zwsp = chr(0x202E), chr(0x9B), chr(0x200B)
    report = ScanReport(categories=[], files_scanned=1)
    report.categories.append(
        CategoryResult(
            name="Permissive defaults",
            weight=10,
            sites=1,
            findings=[
                Finding(
                    rule="permissive-defaults",
                    file=f"safe{rlo}gnp.py",
                    line=1,
                    message=f"flagged{csi}[2J",
                    fix=f"fix{zwsp}it",
                )
            ],
        )
    )

    _print_report(report, "target", None)

    out = capsys.readouterr().out
    for raw in (rlo, csi, zwsp):
        assert raw not in out
    assert "safe\\u202egnp.py" in out
    assert "flagged\\x9b[2J" in out
    assert "fix\\u200bit" in out


def test_unknown_config_key_is_a_usage_error(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.agentgauge]\nexcludes = ['x']\n")
    (tmp_path / "server.py").write_text("x = 1\n")

    code = main([str(tmp_path)])

    assert code == 2
    assert "unknown key" in capsys.readouterr().err


def test_scan_with_no_applicable_sites_says_so(tmp_path, capsys):
    (tmp_path / "server.py").write_text("def add(a, b):\n    return a + b\n")

    code = main([str(tmp_path)])

    captured = capsys.readouterr()
    assert code == 0
    assert "100.0 / 100" in captured.out
    assert "absence of anything to check" in captured.err


def _break_the_pipe(monkeypatch):
    """Make every print in cli.py raise BrokenPipeError, the way a closed
    pipe does, without touching the real stdout descriptor pytest is using.
    A module-level `print` shadows the builtin for that module only."""
    def exploding_print(*_args, **_kwargs):
        raise BrokenPipeError

    monkeypatch.setattr(cli, "print", exploding_print, raising=False)
    redirected = []
    monkeypatch.setattr(cli.os, "dup2", lambda *a: redirected.append(a))
    return redirected


def test_closed_stdout_pipe_does_not_break_the_exit_code(tmp_path, monkeypatch):
    # `agentgauge . --json | head -1` closes the pipe mid-write. That is a
    # consumer finishing early, not a scan failure, so the exit code must
    # still reflect the governance result.
    (tmp_path / "bad.py").write_text(
        "import shutil\ndef wipe(path):\n    shutil.rmtree(path)\n"
    )
    redirected = _break_the_pipe(monkeypatch)

    assert main([str(tmp_path), "--json"]) == 1
    assert redirected  # stdout was pointed at the null device


def test_closed_stdout_pipe_on_the_human_report_is_also_survivable(
    tmp_path, monkeypatch
):
    (tmp_path / "ok.py").write_text("auto_approve = False\n")
    _break_the_pipe(monkeypatch)

    assert main([str(tmp_path)]) == 0


def test_closed_stdout_pipe_on_sarif_is_survivable(tmp_path, monkeypatch):
    (tmp_path / "ok.py").write_text("auto_approve = True\n")
    _break_the_pipe(monkeypatch)

    assert main([str(tmp_path), "--sarif"]) == 0
