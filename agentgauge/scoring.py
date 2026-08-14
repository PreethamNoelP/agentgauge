"""Scoring aggregator: run every rule over every parsed file, merge the
per-file (sites, passed, findings) tuples into per-category CategoryResults,
and wrap them in a ScanReport with the 0-100 governance score.

Contexts are consumed one at a time, so peak memory is a single file's
AST no matter how large the scanned repo is.

No rule logic lives here and no point math either -- points are derived in
CategoryResult.score. This module only counts and collects -- plus two
scan-wide concerns that don't belong inside any single rule: skipping
disabled rules entirely, and honoring inline `# agentgauge: ignore`
suppressions by converting a suppressed finding into a pass rather than
just hiding it (a hidden failure would silently understate the score).
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
    suppressed: int = 0
    critical_suppressed: int = 0

    @property
    def score(self) -> float:
        return sum(c.score for c in self.categories)

    @property
    def max_score(self) -> int:
        """Normally 100. Lower only if [tool.agentgauge] disabled_rules
        removed a category from this scan entirely -- the max score shrinks
        honestly rather than silently renormalizing the rest up to 100,
        which would hide that a category was turned off at all."""
        return sum(c.weight for c in self.categories)

    @property
    def verdict(self) -> str:
        """PASS / FAIL_CRITICAL / INCOMPLETE -- a gate independent of the
        0-100 score. A single ungated critical action (payment, file
        delete, shell exec, code exec, remote delete) must fail outright;
        averaging it against every other compliant site would dilute a
        catastrophic finding into a passing score (issue #1). Skipped files
        mean the scan didn't see the whole picture, so a clean result over
        a partial view is not a full PASS either.

        An inline `# agentgauge: ignore` suppression on a *critical* finding
        still trips this gate -- it is removed from the visible findings
        list and credited toward the score (see score_contexts), but it
        must not be able to buy back FAIL_CRITICAL. A one-line comment
        silently clearing the one guarantee this tool exists to make would
        just be issue #1 wearing a suppression comment instead of an
        average; critical_suppressed exists specifically so it can't.
        """
        if any(f.critical for f in self.findings) or self.critical_suppressed:
            return "FAIL_CRITICAL"
        if self.skipped:
            return "INCOMPLETE"
        return "PASS"

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
            "max_score": self.max_score,
            "verdict": self.verdict,
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
            "suppressed": self.suppressed,
            "critical_suppressed": self.critical_suppressed,
        }


def score_contexts(
    contexts: Iterable[FileContext],
    disabled_rules: frozenset[str] = frozenset(),
) -> ScanReport:
    active_rules = [rule for rule in ALL_RULES if rule.RULE_ID not in disabled_rules]
    categories = [
        CategoryResult(name=rule.CATEGORY, weight=rule.WEIGHT)
        for rule in active_rules
    ]
    files_scanned = 0
    suppressed = 0
    critical_suppressed = 0
    for ctx in contexts:  # one context alive at a time; never materialized
        files_scanned += 1
        for rule, cat in zip(active_rules, categories):
            sites, passed, findings = rule.check(ctx)
            kept = []
            for f in findings:
                # An inline suppression turns a failing site into a passing
                # one -- a human made a visible, on-the-record decision to
                # accept the risk, which is itself a form of oversight. It
                # must not just vanish, or the score would look better than
                # the scan actually found. But a *critical* one still counts
                # against the verdict (see ScanReport.verdict) -- suppressing
                # the noise must not double as suppressing the one gate this
                # tool cannot let a score buy back.
                if ctx.is_suppressed(f.rule, f.line):
                    passed += 1
                    suppressed += 1
                    if f.critical:
                        critical_suppressed += 1
                else:
                    kept.append(f)
            cat.sites += sites
            cat.passed += passed
            cat.findings.extend(kept)
    return ScanReport(
        categories=categories,
        files_scanned=files_scanned,
        suppressed=suppressed,
        critical_suppressed=critical_suppressed,
    )
