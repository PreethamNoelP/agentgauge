import pytest

from agentgauge.astutils import FileContext
from agentgauge.config import RuleConfig
from agentgauge.scoring import ALL_RULES, score_contexts


def ctx(src: str, path: str = "mem.py", config: RuleConfig | None = None) -> FileContext:
    return FileContext.from_source(src, path=path, config=config)


WIDE_OPEN = (
    "def wipe(path):\n"
    "    shutil.rmtree(path)\n"
)

FULLY_GOVERNED = (
    "@mcp.tool()\n"
    "def wipe(path):\n"
    "    if not path.startswith('/data/'):\n"
    "        raise ValueError('outside sandbox')\n"
    "    if not request_approval('wipe', path):\n"
    "        return False\n"
    "    rate_limiter.acquire()\n"
    "    try:\n"
    "        shutil.rmtree(path)\n"
    "    except OSError as exc:\n"
    "        logger.error('wipe failed: %s', exc)\n"
    "    audit_log('wipe', path)\n"
    "    return True\n"
)


def test_rule_weights_sum_to_100():
    assert sum(rule.WEIGHT for rule in ALL_RULES) == 100


def test_benign_code_scores_100():
    report = score_contexts([ctx("def add(a, b):\n    return a + b\n")])
    assert report.score == 100.0
    assert report.findings == []


def test_wide_open_tool_scores_10():
    # Fails oversight, audit, rate limit, error handling, and validation;
    # only permissive-defaults passes (no flags exist -> full 10).
    report = score_contexts([ctx(WIDE_OPEN)])
    assert report.score == 10.0


def test_fully_governed_tool_scores_100():
    # Same dangerous action, every control present.
    report = score_contexts([ctx(FULLY_GOVERNED)])
    assert report.score == 100.0
    assert report.findings == []


def test_sites_aggregate_across_files():
    report = score_contexts(
        [ctx(WIDE_OPEN, "bad.py"), ctx(FULLY_GOVERNED, "good.py")]
    )
    oversight = next(c for c in report.categories if c.name == "Human oversight")
    assert (oversight.sites, oversight.passed) == (2, 1)
    assert oversight.score == 12.5


def test_findings_are_sorted_by_location():
    report = score_contexts(
        [ctx(WIDE_OPEN, "b.py"), ctx(WIDE_OPEN, "a.py")]
    )
    locations = [(f.file, f.line) for f in report.findings]
    assert locations == sorted(locations)


def test_score_contexts_accepts_a_lazy_iterable():
    # The scanner streams contexts through a generator; scoring must never
    # need the whole set at once.
    report = score_contexts(
        ctx(src, f"f{i}.py")
        for i, src in enumerate([WIDE_OPEN, FULLY_GOVERNED])
    )
    assert report.files_scanned == 2
    assert report.score == 55.0  # midpoint: one all-fail file, one all-pass


# --- verdict: a gate independent of the 0-100 score ---

def test_clean_scan_with_applicable_sites_is_pass():
    # A PASS has to be earned against something. This source has real
    # sites and passes all of them.
    report = score_contexts([ctx(FULLY_GOVERNED)])
    assert report.total_sites > 0
    assert report.verdict == "PASS"


def test_zero_applicable_sites_is_incomplete_not_pass():
    # Before: every category scores full marks when it never applied, so a
    # file agentgauge recognized nothing in scored 100.0/100 and reported
    # PASS -- exit 0 even under `--min-score 100 --fail-on-incomplete`,
    # the strictest invocation there is. The arithmetic was right and the
    # conclusion a CI consumer drew from it was wrong.
    report = score_contexts([ctx("def add(a, b):\n    return a + b\n")])

    assert report.score == 100.0
    assert report.total_sites == 0
    assert report.verdict == "INCOMPLETE"


def test_critical_finding_fails_verdict_regardless_of_score():
    report = score_contexts([ctx(WIDE_OPEN)])
    assert report.verdict == "FAIL_CRITICAL"


def test_non_critical_finding_alone_does_not_fail_verdict():
    # A permissive-defaults finding with no accompanying sensitive call is
    # not critical; it must lower the score without tripping the gate.
    report = score_contexts([ctx("auto_approve = True\n")])
    assert report.findings and not any(f.critical for f in report.findings)
    assert report.verdict == "PASS"


def test_skipped_files_mark_verdict_incomplete():
    report = score_contexts([ctx(FULLY_GOVERNED)])
    report.skipped = ["broken.py: syntax error at line 1"]
    assert report.verdict == "INCOMPLETE"


def _governed_payment_tool(i: int) -> str:
    return (
        f"@mcp.tool()\n"
        f"def pay_{i}(amount):\n"
        "    if amount <= 0:\n"
        "        raise ValueError('bad amount')\n"
        "    if not request_approval('pay', amount):\n"
        "        return False\n"
        "    rate_limiter.acquire()\n"
        "    try:\n"
        "        gateway.charge(amount)\n"
        "    except OSError as exc:\n"
        "        logger.error('pay failed: %s', exc)\n"
        "        return False\n"
        "    audit_log('pay', amount)\n"
        "    return True\n\n"
    )


def _payment_tool_missing_approval(i: int) -> str:
    return (
        f"@mcp.tool()\n"
        f"def pay_{i}(amount):\n"
        "    if amount <= 0:\n"
        "        raise ValueError('bad amount')\n"
        "    rate_limiter.acquire()\n"
        "    try:\n"
        "        gateway.charge(amount)\n"
        "    except OSError as exc:\n"
        "        logger.error('pay failed: %s', exc)\n"
        "        return False\n"
        "    audit_log('pay', amount)\n"
        "    return True\n\n"
    )


def test_single_ungated_critical_action_cannot_be_diluted_to_a_pass():
    # Regression for critical-site dilution: 99 fully-governed
    # payment tools plus one missing only its approval check scored 99.75
    # and sailed past --min-score 90 despite a live, unguarded payment call.
    # The verdict must catch what the averaged score hides.
    src = _payment_tool_missing_approval(0) + "".join(
        _governed_payment_tool(i) for i in range(1, 100)
    )
    report = score_contexts([ctx(src)])

    assert report.score == pytest.approx(99.75)
    assert report.verdict == "FAIL_CRITICAL"


# --- disabled rules (config-driven) ---

def test_disabling_a_rule_removes_its_category_and_shrinks_max_score():
    config = RuleConfig(disabled_rules=frozenset({"rate-limiting"}))
    report = score_contexts(
        [ctx("@mcp.tool()\ndef fetch(url):\n    return http.get(url)\n", config=config)],
        disabled_rules=config.disabled_rules,
    )
    assert "Rate limiting" not in {c.name for c in report.categories}
    assert report.max_score == 85


def test_disabled_rule_findings_never_appear():
    config = RuleConfig(disabled_rules=frozenset({"rate-limiting"}))
    report = score_contexts(
        [ctx("@mcp.tool()\ndef fetch(url):\n    return http.get(url)\n", config=config)],
        disabled_rules=config.disabled_rules,
    )
    assert all(f.rule != "rate-limiting" for f in report.findings)


def test_no_disabled_rules_keeps_max_score_at_100():
    report = score_contexts([ctx("x = 1\n")])
    assert report.max_score == 100


# --- inline suppression ---

def test_suppressed_finding_counts_as_passed_and_is_hidden():
    report = score_contexts(
        [ctx("auto_approve = True  # agentgauge: ignore\n")]
    )
    assert report.findings == []
    assert report.suppressed == 1
    defaults_cat = next(c for c in report.categories if c.name == "Permissive defaults")
    assert (defaults_cat.sites, defaults_cat.passed) == (1, 1)


def test_suppression_scoped_to_a_different_rule_does_not_apply():
    report = score_contexts(
        [ctx("auto_approve = True  # agentgauge: ignore[human-oversight]\n")]
    )
    assert len(report.findings) == 1
    assert report.findings[0].rule == "permissive-defaults"


def test_suppressing_a_critical_finding_still_forces_fail_critical():
    # A one-line comment must not be able to buy back the one guarantee
    # that score-averaging itself is barred from buying back.
    report = score_contexts(
        [ctx(
            "def wipe(path):\n"
            "    shutil.rmtree(path)  # agentgauge: ignore[human-oversight]\n"
        )]
    )
    assert all(f.rule != "human-oversight" for f in report.findings)  # noise gone...
    assert report.critical_suppressed == 1
    assert report.verdict == "FAIL_CRITICAL"  # ...but the gate still holds


def test_suppressing_a_non_critical_finding_does_not_affect_verdict():
    report = score_contexts(
        [ctx("auto_approve = True  # agentgauge: ignore\n")]
    )
    assert report.critical_suppressed == 0
    assert report.verdict == "PASS"


# --- suppression comments that do not do what their author meant ---

def test_malformed_suppression_is_reported_as_a_warning():
    ctx = FileContext.from_source(
        "import shutil\n"
        "def wipe(path):\n"
        "    shutil.rmtree(path)  # agentgauge: ignore[]\n",
        path="mem.py",
    )
    report = score_contexts([ctx])

    assert report.suppressed == 0
    assert report.verdict == "FAIL_CRITICAL"
    assert any("malformed" in w for w in report.warnings)


def test_unknown_rule_id_in_a_suppression_is_reported_as_a_warning():
    ctx = FileContext.from_source(
        "auto_approve = True  # agentgauge: ignore[permissive-default]\n",
        path="mem.py",
    )
    report = score_contexts([ctx])

    assert report.suppressed == 0
    assert any("unknown rule 'permissive-default'" in w for w in report.warnings)


def test_valid_suppression_produces_no_warning():
    ctx = FileContext.from_source(
        "auto_approve = True  # agentgauge: ignore[permissive-defaults]\n",
        path="mem.py",
    )
    report = score_contexts([ctx])

    assert report.suppressed == 1
    assert report.warnings == []


# --- disabling a rule must not be able to buy back the verdict ---

def test_disabling_human_oversight_cannot_produce_a_pass():
    # Before: disabled_rules = ["human-oversight"] removed the only rule
    # that marks findings critical, so an ungated shutil.rmtree scored
    # a clean PASS and exited 0 -- the whole point of the gate, defeated
    # by one config line.
    report = score_contexts(
        [ctx("import shutil\ndef wipe(path):\n    shutil.rmtree(path)\n")],
        disabled_rules=frozenset({"human-oversight"}),
    )

    assert report.verdict == "INCOMPLETE"
    assert report.gate_disabled == ("human-oversight",)
    assert report.to_dict()["critical_gate_active"] is False
    assert any("FAIL_CRITICAL gate" in w for w in report.warnings)


def test_disabling_a_non_gate_rule_leaves_the_verdict_alone():
    report = score_contexts(
        [ctx("auto_approve = True\n")],
        disabled_rules=frozenset({"rate-limiting"}),
    )

    assert report.verdict == "PASS"
    assert report.gate_disabled == ()
    assert report.to_dict()["critical_gate_active"] is True


# --- a score over zero applicable sites is not evidence of governance ---

def test_zero_applicable_sites_is_reported_as_such():
    report = score_contexts([ctx("def add(a, b):\n    return a + b\n")])

    assert report.score == 100.0
    assert report.total_sites == 0
    assert any("absence of anything to check" in w for w in report.warnings)


def test_any_applicable_site_suppresses_the_zero_site_warning():
    report = score_contexts([ctx("auto_approve = False\n")])

    assert report.total_sites == 1
    assert report.warnings == []


def test_findings_order_is_fully_specified():
    # Two findings can share a file and line (one sensitive call is a site
    # for both oversight and error handling). Their relative order must not
    # depend on rule registration order, or two runs of the same commit
    # would produce different JSON.
    report = score_contexts([ctx("import shutil\ndef f(p):\n    shutil.rmtree(p)\n")])

    same_line = [f for f in report.findings if f.line == 3]
    assert [f.rule for f in same_line] == sorted(f.rule for f in same_line)
    assert report.findings == sorted(
        report.findings, key=lambda f: (f.file, f.line, f.rule, f.message)
    )
