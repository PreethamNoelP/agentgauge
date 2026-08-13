from agentgauge.astutils import FileContext
from agentgauge.config import RuleConfig
from agentgauge.rules import ratelimit


def run(src: str, config: RuleConfig | None = None):
    return ratelimit.check(FileContext.from_source(src, path="mem.py", config=config))


def test_tool_without_rate_limit_fails():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def fetch(url):\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed) == (1, 0)
    assert "'fetch'" in findings[0].message


def test_limiter_decorator_passes():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "@limiter.limit('10/minute')\n"
        "def fetch(url):\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_ratelimit_library_limits_decorator_passes():
    sites, passed, _ = run(
        "@tool\n"
        "@limits(calls=10, period=60)\n"
        "def fetch(url):\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed) == (1, 1)


def test_inline_throttle_reference_passes():
    sites, passed, _ = run(
        "@mcp.tool()\n"
        "def fetch(url):\n"
        "    throttle.wait()\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed) == (1, 1)


def test_generic_limit_param_does_not_count():
    # `limit=10` is pagination, not rate limiting. Must still fail.
    sites, passed, _ = run(
        "@mcp.tool()\n"
        "def search(query, limit=10):\n"
        "    return db.find(query, limit)\n"
    )
    assert (sites, passed) == (1, 0)


def test_plain_helper_is_not_a_site():
    sites, passed, findings = run("def add(a, b):\n    return a + b\n")
    assert (sites, passed, findings) == (0, 0, [])


def test_assume_external_rate_limiting_makes_every_tool_not_applicable():
    config = RuleConfig(assume_external_rate_limiting=True)
    sites, passed, findings = run(
        "@mcp.tool()\ndef fetch(url):\n    return http.get(url)\n",
        config=config,
    )
    assert (sites, passed, findings) == (0, 0, [])


def test_extra_rate_marker_from_config_is_recognized():
    config = RuleConfig(rate_markers=("throughput_cap",))
    sites, passed, _ = run(
        "@mcp.tool()\ndef fetch(url):\n    throughput_cap.check()\n    return http.get(url)\n",
        config=config,
    )
    assert (sites, passed) == (1, 1)
