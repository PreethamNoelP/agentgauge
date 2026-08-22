"""End-to-end proof: the full pipeline separates a realistic vulnerable
server from a realistic clean one, decisively."""

import subprocess
import sys
from pathlib import Path

from agentgauge.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).parent.parent

ALL_RULE_IDS = {
    "human-oversight",
    "audit-logging",
    "rate-limiting",
    "error-handling",
    "input-validation",
    "permissive-defaults",
}


def test_vulnerable_server_scores_zero_and_every_category_fires():
    report = scan(FIXTURES / "vulnerable_server.py")

    assert report.score == 0.0
    assert {f.rule for f in report.findings} == ALL_RULE_IDS
    assert report.verdict == "FAIL_CRITICAL"


def test_clean_server_scores_perfect_with_no_findings():
    # The false-positive canary: legitimate governance patterns must
    # never be flagged.
    report = scan(FIXTURES / "clean_server.py")

    assert report.score == 100.0
    assert report.findings == []
    assert report.verdict == "PASS"


def test_python_dash_m_entrypoint_end_to_end():
    # A real subprocess proves the __main__ wiring and exit-code
    # propagation that in-process main() calls cannot.
    proc = subprocess.run(
        [sys.executable, "-m", "agentgauge", str(FIXTURES / "clean_server.py")],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    assert proc.returncode == 0
    assert "100.0 / 100" in proc.stdout


def test_min_score_gate_end_to_end():
    proc = subprocess.run(
        [
            sys.executable, "-m", "agentgauge",
            str(FIXTURES / "vulnerable_server.py"),
            "--min-score", "70",
        ],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    assert proc.returncode == 1


def test_critical_verdict_fails_end_to_end_without_min_score():
    # No --min-score at all: a live critical finding must still fail the
    # build (issue #1) rather than defaulting to a pass.
    proc = subprocess.run(
        [sys.executable, "-m", "agentgauge", str(FIXTURES / "vulnerable_server.py")],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )
    assert proc.returncode == 1
    assert "FAIL_CRITICAL" in proc.stdout


def test_vulnerable_fixture_covers_every_detection_shape():
    # Each shape below is one a previous version of agentgauge scored as
    # clean. Pinning them here means a regression fails the fixture gate
    # in CI, not just a unit test someone might delete.
    report = scan(FIXTURES / "vulnerable_server.py")
    messages = " ".join(f.message for f in report.findings)

    for expected in [
        "subprocess.run",                    # plain dotted sink
        "subprocess.check_call",             # module-level sink
        "shutil.rmtree",                     # rebound sink (rm = shutil.rmtree)
        "unlink",                            # pathlib, dynamic receiver
        "asyncio.create_subprocess_shell",   # async sink
        "pickle.loads",                      # deserialization
        "eval",                              # code exec
        "at module level",                   # scope-limited approval check
    ]:
        assert expected in messages, expected


def test_clean_fixture_exercises_every_category():
    # A false-positive canary is only worth having if every rule actually
    # gets a chance to fire on it.
    report = scan(FIXTURES / "clean_server.py")

    assert report.findings == []
    assert all(c.sites > 0 for c in report.categories), [
        c.name for c in report.categories if c.sites == 0
    ]
