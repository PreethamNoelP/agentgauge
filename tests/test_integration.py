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


def test_clean_server_scores_perfect_with_no_findings():
    # The false-positive canary: legitimate governance patterns must
    # never be flagged.
    report = scan(FIXTURES / "clean_server.py")

    assert report.score == 100.0
    assert report.findings == []


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
