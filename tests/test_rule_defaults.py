from agentgauge.astutils import FileContext
from agentgauge.config import RuleConfig
from agentgauge.rules import defaults


def run(src: str, config: RuleConfig | None = None):
    return defaults.check(FileContext.from_source(src, path="mem.py", config=config))


def test_auto_approve_true_assignment_fails():
    sites, passed, findings = run("auto_approve = True\n")
    assert (sites, passed) == (1, 0)
    assert "auto_approve" in findings[0].message


def test_require_approval_false_keyword_fails():
    sites, passed, findings = run("agent = Agent(require_approval=False)\n")
    assert (sites, passed) == (1, 0)
    assert "require_approval" in findings[0].message


def test_safe_setting_is_a_passing_site():
    sites, passed, findings = run("require_approval = True\n")
    assert (sites, passed, findings) == (1, 1, [])


def test_permissive_parameter_default_fails():
    sites, passed, _ = run(
        "def run_tool(cmd, auto_approve=True):\n"
        "    pass\n"
    )
    assert (sites, passed) == (1, 0)


def test_ssl_verify_false_fails():
    sites, passed, _ = run("requests.get(url, verify=False)\n")
    assert (sites, passed) == (1, 0)


def test_constant_case_and_attribute_targets_are_matched():
    # AUTO_APPROVE and settings.auto_approve normalize to the same flag.
    sites, passed, _ = run(
        "AUTO_APPROVE = True\n"
        "settings.auto_approve = True\n"
    )
    assert (sites, passed) == (2, 0)


def test_non_constant_binding_is_not_a_site():
    # We can't statically judge load_config()'s value -> not a site.
    sites, passed, findings = run("require_approval = load_config()\n")
    assert (sites, passed, findings) == (0, 0, [])


def test_no_flags_means_no_sites():
    sites, passed, findings = run("x = 1\ndo_thing(y=2)\n")
    assert (sites, passed, findings) == (0, 0, [])


def test_extra_dangerous_when_true_flag_from_config_is_recognized():
    config = RuleConfig(dangerous_when_true=frozenset({"yolo_mode"}))
    sites, passed, findings = run("yolo_mode = True\n", config=config)
    assert (sites, passed) == (1, 0)
    assert "yolo_mode" in findings[0].message


def test_extra_dangerous_when_true_flag_matches_regardless_of_underscores():
    config = RuleConfig(dangerous_when_true=frozenset({"yolo_mode"}))
    sites, passed, _ = run("YOLOMODE = True\n", config=config)
    assert (sites, passed) == (1, 0)
