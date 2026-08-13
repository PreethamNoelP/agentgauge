"""Optional project configuration: `[tool.agentgauge]` in pyproject.toml.

Reading a config file is opt-in in effect, not just in name: every field
defaults to the exact behavior agentgauge had before this module existed
(nothing excluded, nothing disabled, no extra vocabulary). A scan with no
config file present behaves identically to one that finds an empty table.

Two independent concerns are split into two dataclasses:
  - RuleConfig travels with every FileContext and is read by rule modules
    (vocabulary extensions, assume_external_rate_limiting).
  - Config is scan-level only (which rules run at all, min-score default,
    path excludes) and is consumed by scanner.py / cli.py, never by a rule.
"""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# Recognized [tool.agentgauge] keys that extend a rule's built-in vocabulary,
# additively -- a config can only add markers, never remove the defaults
# documented in RULES.md.
_VOCAB_KEYS = {
    "extra_approval_markers": "approval_markers",
    "extra_log_tokens": "log_tokens",
    "extra_rate_limit_markers": "rate_markers",
    "extra_validation_tokens": "validation_tokens",
    "extra_risky_params": "risky_param_tokens",
    "extra_dangerous_when_true": "dangerous_when_true",
    "extra_dangerous_when_false": "dangerous_when_false",
}

_TUPLE_FIELDS = {"approval_markers", "rate_markers"}


class ConfigError(Exception):
    """Raised for a present-but-malformed config file. Never raised for a
    missing one -- no config file is the common case, not an error."""


@dataclass(frozen=True)
class RuleConfig:
    """Per-scan settings a rule's check(ctx) may consult via ctx.config."""

    disabled_rules: frozenset[str] = frozenset()
    assume_external_rate_limiting: bool = False
    approval_markers: tuple[str, ...] = ()
    log_tokens: frozenset[str] = frozenset()
    rate_markers: tuple[str, ...] = ()
    validation_tokens: frozenset[str] = frozenset()
    risky_param_tokens: frozenset[str] = frozenset()
    dangerous_when_true: frozenset[str] = frozenset()
    dangerous_when_false: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Config:
    """Everything loaded from [tool.agentgauge]."""

    min_score: float | None = None
    exclude: tuple[str, ...] = ()
    rules: RuleConfig = field(default_factory=RuleConfig)


def _as_str_tuple(value, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"[tool.agentgauge] '{key}' must be a list of strings")
    return tuple(value)


def _build_rule_config(table: dict) -> RuleConfig:
    kwargs = {}

    disabled = table.get("disabled_rules", [])
    kwargs["disabled_rules"] = frozenset(_as_str_tuple(disabled, "disabled_rules"))

    assume_external = table.get("assume_external_rate_limiting", False)
    if not isinstance(assume_external, bool):
        raise ConfigError(
            "[tool.agentgauge] 'assume_external_rate_limiting' must be true/false"
        )
    kwargs["assume_external_rate_limiting"] = assume_external

    for toml_key, field_name in _VOCAB_KEYS.items():
        if toml_key not in table:
            continue
        values = _as_str_tuple(table[toml_key], toml_key)
        normalized = tuple(v.lower() for v in values)
        kwargs[field_name] = (
            normalized if field_name in _TUPLE_FIELDS else frozenset(normalized)
        )

    return RuleConfig(**kwargs)


def _parse(data: dict) -> Config:
    table = data.get("tool", {}).get("agentgauge", {})
    if not isinstance(table, dict):
        raise ConfigError("[tool.agentgauge] must be a table")

    min_score = table.get("min_score")
    if min_score is not None and not isinstance(min_score, (int, float)):
        raise ConfigError("[tool.agentgauge] 'min_score' must be a number")

    exclude = _as_str_tuple(table.get("exclude", []), "exclude")

    return Config(
        min_score=float(min_score) if min_score is not None else None,
        exclude=exclude,
        rules=_build_rule_config(table),
    )


def _discover_path(target: Path) -> Path | None:
    """Look for pyproject.toml next to the scan target: inside it if target
    is a directory, alongside it if target is a single file. No upward
    directory search -- predictable discovery beats "found a config
    somewhere above me" surprise, especially for a CI tool."""
    directory = target if target.is_dir() else target.parent
    candidate = directory / "pyproject.toml"
    return candidate if candidate.is_file() else None


def load_config(target: Path, explicit_path: Path | None = None) -> Config:
    """Load [tool.agentgauge] from an explicit path or by discovery next to
    `target`. Returns the all-defaults Config if nothing is found -- a
    missing config file is not an error, a malformed one is."""
    path = explicit_path if explicit_path is not None else _discover_path(target)
    if path is None:
        return Config()
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    try:
        return _parse(data)
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
