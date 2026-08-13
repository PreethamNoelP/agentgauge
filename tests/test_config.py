import pytest

from agentgauge.config import Config, ConfigError, RuleConfig, load_config


def test_missing_config_file_returns_all_defaults(tmp_path):
    config = load_config(tmp_path)
    assert config == Config()


def test_discovers_pyproject_next_to_directory_target(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.agentgauge]\nmin_score = 80\n"
    )
    config = load_config(tmp_path)
    assert config.min_score == 80.0


def test_discovers_pyproject_next_to_single_file_target(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.agentgauge]\nmin_score = 80\n"
    )
    target = tmp_path / "server.py"
    target.write_text("x = 1\n")
    config = load_config(target)
    assert config.min_score == 80.0


def test_pyproject_without_tool_agentgauge_table_is_all_defaults(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "unrelated"\n'
    )
    config = load_config(tmp_path)
    assert config == Config()


def test_explicit_config_path_overrides_discovery(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.agentgauge]\nmin_score = 10\n")
    custom = tmp_path / "custom.toml"
    custom.write_text("[tool.agentgauge]\nmin_score = 90\n")

    config = load_config(tmp_path, explicit_path=custom)
    assert config.min_score == 90.0


def test_missing_explicit_config_path_is_an_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path, explicit_path=tmp_path / "nope.toml")


def test_malformed_toml_is_an_error(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.agentgauge\nmin_score = 1\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_min_score_must_be_a_number(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.agentgauge]\nmin_score = "high"\n'
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_exclude_reads_a_list_of_globs(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.agentgauge]\nexclude = ["tests/fixtures/*", "**/generated_*.py"]\n'
    )
    config = load_config(tmp_path)
    assert config.exclude == ("tests/fixtures/*", "**/generated_*.py")


def test_disabled_rules_reads_into_rule_config(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.agentgauge]\ndisabled_rules = ["rate-limiting"]\n'
    )
    config = load_config(tmp_path)
    assert config.rules.disabled_rules == frozenset({"rate-limiting"})


def test_assume_external_rate_limiting_must_be_boolean(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.agentgauge]\nassume_external_rate_limiting = "yes"\n'
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_extra_vocabulary_lists_populate_rule_config(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.agentgauge]\n"
        'extra_approval_markers = ["vet"]\n'
        'extra_log_tokens = ["telemetry"]\n'
        'extra_risky_params = ["apikey"]\n'
    )
    config = load_config(tmp_path)
    assert config.rules.approval_markers == ("vet",)
    assert config.rules.log_tokens == frozenset({"telemetry"})
    assert config.rules.risky_param_tokens == frozenset({"apikey"})


def test_extra_vocabulary_must_be_a_list_of_strings(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.agentgauge]\nextra_log_tokens = "telemetry"\n'
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_rule_config_defaults_are_all_empty():
    rules = RuleConfig()
    assert rules.disabled_rules == frozenset()
    assert rules.assume_external_rate_limiting is False
    assert rules.approval_markers == ()
    assert rules.log_tokens == frozenset()
