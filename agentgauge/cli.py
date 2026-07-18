"""Command-line interface: `python -m agentgauge <path> [--json] [--min-score N]`.

Exit codes are the contract for CI:
  0  scan completed (and met --min-score, if given)
  1  score below --min-score
  2  bad invocation (target missing, or no Python files actually scanned)
"""

import argparse
import json
import sys
from pathlib import Path

from agentgauge.scanner import scan
from agentgauge.scoring import ScanReport


def _print_report(report: ScanReport, target: str) -> None:
    print(f"agentgauge: {target}")
    print(f"scanned {report.files_scanned} Python file(s)\n")

    for c in report.categories:
        status = (
            "(no applicable sites)"
            if c.sites == 0
            else f"({c.passed}/{c.sites} sites passed)"
        )
        print(f"  {c.name:<34}{c.score:>6.1f} / {c.weight:<3} {status}")
    print("  " + "-" * 58)
    print(f"  {'GOVERNANCE SCORE':<34}{report.score:>6.1f} / 100")

    if report.findings:
        print(f"\nFindings ({len(report.findings)}):")
        for f in report.findings:
            print(f"\n  {f.file}:{f.line}  [{f.rule}]")
            print(f"    {f.message}")
            print(f"    fix: {f.fix}")

    for entry in report.skipped:
        print(f"warning: skipped {entry}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentgauge",
        description="Static governance scanner for MCP servers and "
                    "AI agent tool-calling code.",
    )
    parser.add_argument("target", help="Python file or repo directory to scan")
    parser.add_argument(
        "--json", action="store_true", help="emit a machine-readable JSON report"
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        metavar="N",
        help="exit with code 1 if the governance score is below N",
    )
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        # Without this check, scanning a typo'd path would find zero files,
        # zero sites -- and report a perfect 100.
        print(f"agentgauge: target not found: {target}", file=sys.stderr)
        return 2

    report = scan(target)

    if report.files_scanned == 0:
        # A score over zero evidence is vacuous, and a vacuous score must
        # not look like a passing one. Covers empty repos, non-Python repos,
        # and directories where every file failed to parse.
        for entry in report.skipped:
            print(f"warning: skipped {entry}", file=sys.stderr)
        print(
            f"agentgauge: no Python files scanned under {target} -- "
            "refusing to report a score based on zero evidence",
            file=sys.stderr,
        )
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_report(report, args.target)

    if args.min_score is not None and report.score < args.min_score:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
