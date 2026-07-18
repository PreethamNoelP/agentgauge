from agentgauge.astutils import FileContext
from agentgauge.scoring import ALL_RULES, score_contexts


def ctx(src: str, path: str = "mem.py") -> FileContext:
    return FileContext.from_source(src, path=path)


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
