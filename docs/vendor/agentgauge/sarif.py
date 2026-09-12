"""SARIF 2.1.0 rendering: the format GitHub/GitLab code scanning, and most
enterprise AppSec dashboards, ingest natively. Kept separate from
scoring.py's ScanReport.to_dict() -- that one is agentgauge's own JSON
shape, this one exists purely to satisfy an external spec, and the two
should be free to diverge without either implementation leaking into the
other.

https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from typing import Any

from agentgauge import __version__
from agentgauge.scoring import ALL_RULES, ScanReport

SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)

_RULE_INDEX = {rule.RULE_ID: i for i, rule in enumerate(ALL_RULES)}


def _rule_descriptors() -> list[dict[str, Any]]:
    """One SARIF reportingDescriptor per registered rule, regardless of
    whether it produced a finding in this particular scan -- a stable rule
    catalog is what lets a dashboard track a rule's history across scans."""
    return [
        {
            "id": rule.RULE_ID,
            "name": rule.CATEGORY.replace(" ", ""),
            "shortDescription": {"text": rule.CATEGORY},
            "help": {"text": rule.__doc__ or rule.CATEGORY},
            "properties": {"category": rule.CATEGORY, "weight": rule.WEIGHT},
        }
        for rule in ALL_RULES
    ]


def _invocation(report: ScanReport, config_source: str | None) -> dict[str, Any]:
    """The run's invocation record: what agentgauge could not read.

    A --sarif consumer sees only `results`, so without this a file skipped
    for a syntax error, an unknown encoding or the size limit would vanish
    from the dashboard entirely -- and silent gaps in coverage are exactly
    what the INCOMPLETE verdict exists to surface.
    """
    invocation: dict[str, Any] = {
        # True even with notifications present: agentgauge itself ran to
        # completion. Per-file failures are reported, not run failures.
        "executionSuccessful": True,
        "toolExecutionNotifications": [
            {"level": "warning", "message": {"text": text}}
            for text in [f"skipped {entry}" for entry in report.skipped]
            + list(report.warnings)
        ],
    }
    if config_source is not None:
        invocation["properties"] = {"configSource": config_source}
    return invocation


def build_sarif(
    report: ScanReport, config_source: str | None = None
) -> dict[str, Any]:
    """Render a ScanReport as a SARIF 2.1.0 log. `critical` findings map to
    SARIF "error" level (build-breaking); everything else maps to "warning"
    -- mirroring the same critical/non-critical split the verdict itself
    uses, so a code-scanning dashboard's severity filter agrees with
    agentgauge's own exit code."""
    results = [
        {
            "ruleId": f.rule,
            "ruleIndex": _RULE_INDEX[f.rule],
            "level": "error" if f.critical else "warning",
            "message": {"text": f"{f.message} Fix: {f.fix}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    }
                }
            ],
        }
        for f in report.findings
    ]

    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentgauge",
                        # A dashboard tracking a rule's behavior over time
                        # needs to know which build of the tool produced a
                        # result; without it, a detection change looks like
                        # a code change.
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/PreethamNoelP/agentgauge",
                        "rules": _rule_descriptors(),
                    }
                },
                "invocations": [_invocation(report, config_source)],
                "results": results,
                "properties": {
                    "score": round(report.score, 1),
                    "maxScore": report.max_score,
                    "verdict": report.verdict,
                    "filesScanned": report.files_scanned,
                    "excluded": report.excluded,
                    "totalSites": report.total_sites,
                    "suppressed": report.suppressed,
                    "criticalSuppressed": report.critical_suppressed,
                    "criticalGateActive": not report.gate_disabled,
                },
            }
        ],
    }
