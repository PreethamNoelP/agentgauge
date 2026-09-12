"""Command-line interface: `agentgauge <path> [--json|--sarif] [--min-score N]`.

Exit codes are the contract for CI:
  0  scan completed, met --min-score (if given), and no critical failures
  1  score below --min-score, OR the verdict is FAIL_CRITICAL -- a single
     ungated critical action (payment, file delete, shell exec, ...) fails
     the build regardless of --min-score or how high the aggregate score is
     -- OR the verdict is INCOMPLETE and --fail-on-incomplete was passed
  2  bad invocation (target missing, no Python files actually scanned, or
     an explicit/discovered [tool.agentgauge] config file is malformed)
"""

import argparse
import json
import os
import sys
from pathlib import Path

from agentgauge import __version__
from agentgauge.config import ConfigError, load_config
from agentgauge.sarif import build_sarif
from agentgauge.scanner import scan
from agentgauge.scoring import ScanReport

# Scanned repositories are untrusted input, and file names reach the
# terminal verbatim. A path containing an ANSI escape (legal on Linux and
# macOS) could otherwise repaint or erase the report a reviewer is reading.
_ESCAPES: dict[int, str] = {c: f"\\x{c:02x}" for c in range(32)}
_ESCAPES[127] = "\\x7f"
_ESCAPES[ord("\t")] = "    "

# C1 controls. A terminal in 8-bit mode reads 0x9b as CSI -- the single-byte
# equivalent of the ESC-[ that the C0 range above already defangs -- so
# escaping only C0 left the same capability reachable through a different
# encoding of it.
_ESCAPES.update({c: f"\\x{c:02x}" for c in range(0x80, 0xA0)})

# Characters that reorder or hide text without being "control characters" at
# all. A file named with U+202E RIGHT-TO-LEFT OVERRIDE makes the rest of a
# finding line render in reverse, so a reviewer reading the report sees a
# path, rule id or fix that is not the one agentgauge found -- the Trojan
# Source trick (CVE-2021-42574) pointed at the report instead of at source.
# Zero-width characters hide content in the same spirit. None of these have
# any legitimate place in a rendered finding, so they are shown escaped
# rather than obeyed.
_ESCAPES.update(
    {
        c: f"\\u{c:04x}"
        for c in (
            *range(0x202A, 0x202F),  # LRE RLE PDF LRO RLO
            *range(0x2066, 0x206A),  # LRI RLI FSI PDI
            0x200B,                  # zero-width space
            0x200C,                  # zero-width non-joiner
            0x200D,                  # zero-width joiner
            0x2060,                  # word joiner
            0xFEFF,                  # zero-width no-break space / BOM
        )
    }
)


def _safe(text: str) -> str:
    """Render text from the scanned repo with control characters defanged."""
    return str(text).translate(_ESCAPES)


def _print_report(report: ScanReport, target: str, config_source: str | None) -> None:
    print(f"agentgauge: {_safe(target)}")
    print(f"scanned {report.files_scanned} Python file(s)", end="")
    print(f" (config: {_safe(config_source)})\n" if config_source else "\n")

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

    # The denominator behind the score, in the one place a reader cannot
    # miss it. A 100.0 over 0 sites and a 100.0 over 200 are the same
    # number and completely different claims; printing only the number let
    # the first pass for the second.
    print(f"  {'APPLICABLE SITES':<34}{report.total_sites}")
    if report.excluded:
        print(f"  {'EXCLUDED BY CONFIG':<34}{report.excluded} file(s)")

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
            print(f"\n  {_safe(f.file)}:{f.line}  [{f.rule}]")
            print(f"    {_safe(f.message)}")
            print(f"    fix: {_safe(f.fix)}")

    _print_warnings(report)


def _print_warnings(report: ScanReport) -> None:
    for entry in report.warnings:
        print(f"warning: {_safe(entry)}", file=sys.stderr)
    for entry in report.skipped:
        print(f"warning: skipped {_safe(entry)}", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentgauge",
        description="Static governance scanner for MCP servers and "
                    "AI agent tool-calling code.",
    )
    parser.add_argument("target", help="Python file or repo directory to scan")
    parser.add_argument(
        "--version", action="version", version=f"agentgauge {__version__}"
    )
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
        "--fail-on-incomplete",
        action="store_true",
        help="exit with code 1 on an INCOMPLETE verdict -- a file that could "
             "not be parsed, or a disabled critical-gate rule, means the scan "
             "did not see everything it claims to cover",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="path to a TOML file with a [tool.agentgauge] table; "
             "default is to look for pyproject.toml next to the target",
    )
    return parser


def _emit(
    report: ScanReport, args: argparse.Namespace, config_source: str | None
) -> None:
    """Write the report in the requested format.

    A consumer closing the pipe (`agentgauge . --json | head`) is a normal
    end to the conversation, not a scan failure: swallow it, point stdout at
    the null device so the interpreter's exit-time flush does not re-raise,
    and let the exit code still reflect the governance result.
    """
    try:
        if args.json:
            payload = report.to_dict()
            payload["config_source"] = config_source
            print(json.dumps(payload, indent=2))
        elif args.sarif:
            print(json.dumps(build_sarif(report, config_source), indent=2))
        else:
            _print_report(report, args.target, config_source)
            return
        _print_warnings(report)
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            # No real file descriptor behind stdout (a captured or wrapped
            # stream). Nothing to redirect, and nothing left to flush.
            pass


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        # Without this check, scanning a typo'd path would find zero files,
        # zero sites -- and report a perfect 100.
        print(f"agentgauge: target not found: {_safe(args.target)}", file=sys.stderr)
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
        _print_warnings(report)
        print(
            f"agentgauge: no Python files scanned under {_safe(args.target)} -- "
            "refusing to report a score based on zero evidence",
            file=sys.stderr,
        )
        return 2

    _emit(report, args, config.source)

    min_score = args.min_score if args.min_score is not None else config.min_score

    if report.verdict == "FAIL_CRITICAL":
        return 1
    if min_score is not None and report.score < min_score:
        return 1
    if args.fail_on_incomplete and report.verdict == "INCOMPLETE":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
