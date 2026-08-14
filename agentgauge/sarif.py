"""SARIF 2.1.0 rendering: the format GitHub/GitLab code scanning, and most
enterprise AppSec dashboards, ingest natively. Kept separate from
scoring.py's ScanReport.to_dict() -- that one is agentgauge's own JSON
shape, this one exists purely to satisfy an external spec, and the two
should be free to diverge without either implementation leaking into the
other.

https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from agentgauge.scoring import ALL_RULES, ScanReport

SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)


def _rule_descriptors() -> list[dict]:
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


def build_sarif(report: ScanReport) -> dict:
    """Render a ScanReport as a SARIF 2.1.0 log. `critical` findings map to
    SARIF "error" level (build-breaking); everything else maps to "warning"
    -- mirroring the same critical/non-critical split the verdict itself
    uses, so a code-scanning dashboard's severity filter agrees with
    agentgauge's own exit code."""
    results = [
        {
            "ruleId": f.rule,
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
                        "informationUri": "https://github.com/PreethamNoelP/agentgauge",
                        "rules": _rule_descriptors(),
                    }
                },
                "results": results,
                "properties": {
                    "score": round(report.score, 1),
                    "maxScore": report.max_score,
                    "verdict": report.verdict,
                },
            }
        ],
    }
