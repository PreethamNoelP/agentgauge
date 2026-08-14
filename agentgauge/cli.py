"""Command-line interface: `python -m agentgauge <path> [--json] [--min-score N]`.

Exit codes are the contract for CI:
  0  scan completed, met --min-score (if given), and no critical failures
  1  score below --min-score, OR the verdict is FAIL_CRITICAL -- a single
     ungated critical action (payment, file delete, shell exec, ...) fails
     the build regardless of --min-score or how high the aggregate score is
  2  bad invocation (target missing, no Python files actually scanned, or
     an explicit/discovered [tool.agentgauge] config file is malformed)
"""

import argparse
import json
import sys
from pathlib import Path

from agentgauge.config import ConfigError, load_config
from agentgauge.sarif import build_sarif
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
    print(f"  {'GOVERNANCE SCORE':<34}{report.score:>6.1f} / {report.max_score}")
    print(f"  {'VERDICT':<34}{report.verdict}")

    if report.suppressed:
        print(f"  ({report.suppressed} finding(s) suppressed by inline comment)")
    if report.critical_suppressed:
        print(
            f"  ({report.critical_suppressed} suppressed finding(s) were critical -- "
            "still counted toward FAIL_CRITICAL; suppression cannot buy back the verdict)"
        )

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
    output_format = parser.add_mutually_exclusive_group()
    output_format.add_argument(
        "--json", action="store_true", help="emit a machine-readable JSON report"
    )
    output_format.add_argument(
        "--sarif",
        action="store_true",
        help="emit a SARIF 2.1.0 report for GitHub/GitLab code scanning",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        metavar="N",
        help="exit with code 1 if the governance score is below N "
             "(overrides [tool.agentgauge] min_score if both are set)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="path to a TOML file with a [tool.agentgauge] table; "
             "default is to look for pyproject.toml next to the target",
    )
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        # Without this check, scanning a typo'd path would find zero files,
        # zero sites -- and report a perfect 100.
        print(f"agentgauge: target not found: {target}", file=sys.stderr)
        return 2

    try:
        config = load_config(target, args.config)
    except ConfigError as exc:
        print(f"agentgauge: {exc}", file=sys.stderr)
        return 2

    report = scan(target, config=config)

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
    elif args.sarif:
        print(json.dumps(build_sarif(report), indent=2))
    else:
        _print_report(report, args.target)

    min_score = args.min_score if args.min_score is not None else config.min_score

    if report.verdict == "FAIL_CRITICAL":
        return 1
    if min_score is not None and report.score < min_score:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
