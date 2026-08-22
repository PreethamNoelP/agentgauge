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

# Rules whose findings are the only source of `critical`, and therefore of
# FAIL_CRITICAL. Disabling one of these does not just drop a category from
# the score -- it removes the gate itself, which is why ScanReport refuses
# to call such a scan a PASS (see ScanReport.verdict).
CRITICAL_GATE_RULES = frozenset({oversight.RULE_ID})


@dataclass
class ScanReport:
    """Everything a scan produced: six category tallies plus bookkeeping."""

    categories: list[CategoryResult]
    files_scanned: int = 0
    skipped: list[str] = field(default_factory=list)
    suppressed: int = 0
    critical_suppressed: int = 0
    # Human-readable notes about the scan itself rather than the code:
    # unparseable or unknown-rule suppression comments, disabled rules that
    # matter to the verdict. Reported, never silently swallowed.
    warnings: list[str] = field(default_factory=list)
    # Critical-gate-bearing rules that config turned off for this scan.
    gate_disabled: tuple[str, ...] = ()

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

        `disabled_rules` cannot buy it back either, for exactly the same
        reason. Turning off the rule that produces critical findings does
        not make the scan clean, it makes it blind -- so a scan without the
        gate is reported INCOMPLETE, never PASS. Unlike a suppression this
        cannot be FAIL_CRITICAL: with the rule switched off we never looked
        for the sinks, so we have no finding to fail on and no honest way to
        claim one. INCOMPLETE is the truthful answer, and
        --fail-on-incomplete is how CI turns it into a red build.
        """
        if any(f.critical for f in self.findings) or self.critical_suppressed:
            return "FAIL_CRITICAL"
        if self.skipped or self.gate_disabled:
            return "INCOMPLETE"
        return "PASS"

    @property
    def total_sites(self) -> int:
        """Applicable sites across every category. Zero means the scan found
        no governance-relevant code at all -- no sensitive calls, no tool
        functions, no flags -- so the score is the "zero sites, full marks"
        rule applied six times over, not evidence of governance."""
        return sum(c.sites for c in self.categories)

    @property
    def findings(self) -> list[Finding]:
        """All findings across categories, in a fully specified order.

        File and line first, then rule and message: two findings can share a
        location (one call is a site for both oversight and error handling),
        and leaving their order to sort stability would make it depend on
        rule registration order -- a diff between two runs of the same
        commit is exactly what a CI consumer must never see.
        """
        return sorted(
            (f for c in self.categories for f in c.findings),
            key=lambda f: (f.file, f.line, f.rule, f.message),
        )

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "max_score": self.max_score,
            "verdict": self.verdict,
            "files_scanned": self.files_scanned,
            "total_sites": self.total_sites,
            "critical_gate_active": not self.gate_disabled,
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
            "warnings": self.warnings,
        }


def _suppression_warnings(ctx: FileContext, known_rule_ids: set[str]) -> list[str]:
    """Report suppression comments that do not do what their author meant.

    A suppression is the one mechanism by which a human overrides this tool,
    so a broken one must be loud. Two shapes are reported: markers that could
    not be parsed at all (they grant no exemption), and well-formed markers
    naming a rule id that does not exist -- usually a typo, and silently
    ineffective otherwise.
    """
    notes = [
        f"{ctx.path}:{line}: malformed agentgauge suppression ({reason}) "
        "-- nothing was suppressed"
        for line, reason in ctx.malformed_suppressions
    ]
    for line, rules in sorted(ctx.suppressions.items()):
        if rules is None:
            continue
        for unknown in sorted(rules - known_rule_ids):
            notes.append(
                f"{ctx.path}:{line}: agentgauge suppression names unknown rule "
                f"'{unknown}' -- it has no effect"
            )
    return notes


def score_contexts(
    contexts: Iterable[FileContext],
    disabled_rules: frozenset[str] = frozenset(),
) -> ScanReport:
    active_rules = [rule for rule in ALL_RULES if rule.RULE_ID not in disabled_rules]
    categories = [
        CategoryResult(name=rule.CATEGORY, weight=rule.WEIGHT)
        for rule in active_rules
    ]
    known_rule_ids = {rule.RULE_ID for rule in ALL_RULES}
    files_scanned = 0
    suppressed = 0
    critical_suppressed = 0
    warnings: list[str] = []
    for ctx in contexts:  # one context alive at a time; never materialized
        files_scanned += 1
        warnings.extend(_suppression_warnings(ctx, known_rule_ids))
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
    gate_disabled = tuple(sorted(disabled_rules & CRITICAL_GATE_RULES))
    for rule_id in gate_disabled:
        warnings.append(
            f"'{rule_id}' is disabled, which removes the FAIL_CRITICAL gate "
            "entirely -- no ungated payment, deletion or shell-exec call can "
            "be detected in this scan, so its verdict is INCOMPLETE"
        )
    report = ScanReport(
        categories=categories,
        files_scanned=files_scanned,
        suppressed=suppressed,
        critical_suppressed=critical_suppressed,
        warnings=warnings,
        gate_disabled=gate_disabled,
    )
    if files_scanned and report.total_sites == 0:
        warnings.append(
            f"no governance-relevant sites found in {files_scanned} file(s): "
            "this score reflects the absence of anything to check, not "
            "evidence of governance"
        )
    return report
