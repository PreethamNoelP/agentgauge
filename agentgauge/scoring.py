"""Scoring aggregator: run every rule over every parsed file, merge the
per-file (sites, passed, findings) tuples into six CategoryResults, and
wrap them in a ScanReport with the 0-100 governance score.

Contexts are consumed one at a time, so peak memory is a single file's
AST no matter how large the scanned repo is.

No rule logic lives here and no point math either -- points are derived in
CategoryResult.score. This module only counts and collects.
"""

from dataclasses import asdict, dataclass, field
from typing import Iterable

from agentgauge.astutils import FileContext
from agentgauge.models import CategoryResult, Finding
from agentgauge.rules import (
    audit,
    defaults,
    errorhandling,
    oversight,
    ratelimit,
    validation,
)

# The single registry every downstream consumer (scanner, CLI) uses.
ALL_RULES = [oversight, audit, ratelimit, errorhandling, validation, defaults]


@dataclass
class ScanReport:
    """Everything a scan produced: six category tallies plus bookkeeping."""

    categories: list[CategoryResult]
    files_scanned: int = 0
    skipped: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return sum(c.score for c in self.categories)

    @property
    def findings(self) -> list[Finding]:
        """All findings across categories, ordered by location."""
        return sorted(
            (f for c in self.categories for f in c.findings),
            key=lambda f: (f.file, f.line),
        )

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "files_scanned": self.files_scanned,
            "categories": [
                {
                    "name": c.name,
                    "weight": c.weight,
                    "sites": c.sites,
                    "passed": c.passed,
                    "score": round(c.score, 1),
                }
                for c in self.categories
            ],
            "findings": [asdict(f) for f in self.findings],
            "skipped": self.skipped,
        }


def score_contexts(contexts: Iterable[FileContext]) -> ScanReport:
    categories = [
        CategoryResult(name=rule.CATEGORY, weight=rule.WEIGHT)
        for rule in ALL_RULES
    ]
    files_scanned = 0
    for ctx in contexts:  # one context alive at a time; never materialized
        files_scanned += 1
        for rule, cat in zip(ALL_RULES, categories):
            sites, passed, findings = rule.check(ctx)
            cat.sites += sites
            cat.passed += passed
            cat.findings.extend(findings)
    return ScanReport(categories=categories, files_scanned=files_scanned)
