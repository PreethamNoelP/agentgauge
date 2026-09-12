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

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentgauge.rules import RULE_IDS

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

# Every key [tool.agentgauge] understands. An unrecognized key is an error,
# not a no-op: "excludes = [...]" or "min_scores = 90" would otherwise scan
# with silently different settings than the author believed they had asked
# for, which for a governance gate is the worst possible failure mode.
_KNOWN_KEYS = frozenset(
    {"min_score", "exclude", "disabled_rules", "assume_external_rate_limiting"}
    | set(_VOCAB_KEYS)
)

# Vocabulary entries are matched as substrings or stems, so a very short one
# matches nearly every identifier: extra_approval_markers = ["e"] makes the
# human-oversight rule pass on any call whose name contains an "e", which
# turns the critical gate off through a config file. Three characters is
# short enough for real words ("vet") and long enough not to be a wildcard.
_MIN_VOCAB_LENGTH = 3


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
    # The file these settings came from, or None when no config was found.
    # Reported by the CLI: "my [tool.agentgauge] table was ignored" is
    # otherwise invisible, and discovery deliberately does not search
    # upwards (see _discover_path). Named by display_path, so it never
    # carries an absolute path into a CI log.
    source: str | None = None


def _as_str_tuple(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"[tool.agentgauge] '{key}' must be a list of strings")
    return tuple(value)


def _as_vocabulary(value: object, key: str) -> tuple[str, ...]:
    """A vocabulary list, rejecting entries too short to be words. See
    _MIN_VOCAB_LENGTH: a one- or two-character marker is a wildcard that
    silently makes its rule pass everywhere."""
    entries = _as_str_tuple(value, key)
    for entry in entries:
        stripped = entry.strip()
        if len(stripped) < _MIN_VOCAB_LENGTH:
            raise ConfigError(
                f"[tool.agentgauge] '{key}' entry {entry!r} is shorter than "
                f"{_MIN_VOCAB_LENGTH} characters -- it would match almost every "
                "identifier and effectively disable the rule"
            )
    return entries


def _build_rule_config(table: dict[str, Any]) -> RuleConfig:
    kwargs: dict[str, Any] = {}

    disabled = _as_str_tuple(table.get("disabled_rules", []), "disabled_rules")
    unknown = sorted(set(disabled) - set(RULE_IDS))
    if unknown:
        raise ConfigError(
            f"[tool.agentgauge] 'disabled_rules' names unknown rule(s) "
            f"{', '.join(repr(u) for u in unknown)}; valid ids are "
            f"{', '.join(RULE_IDS)}"
        )
    kwargs["disabled_rules"] = frozenset(disabled)

    assume_external = table.get("assume_external_rate_limiting", False)
    if not isinstance(assume_external, bool):
        raise ConfigError(
            "[tool.agentgauge] 'assume_external_rate_limiting' must be true/false"
        )
    kwargs["assume_external_rate_limiting"] = assume_external

    for toml_key, field_name in _VOCAB_KEYS.items():
        if toml_key not in table:
            continue
        values = _as_vocabulary(table[toml_key], toml_key)
        normalized = tuple(v.lower() for v in values)
        kwargs[field_name] = (
            normalized if field_name in _TUPLE_FIELDS else frozenset(normalized)
        )

    return RuleConfig(**kwargs)


def _parse(data: dict[str, Any], source: str | None = None) -> Config:
    tool = data.get("tool", {})
    table = tool.get("agentgauge", {}) if isinstance(tool, dict) else {}
    if not isinstance(table, dict):
        raise ConfigError("[tool.agentgauge] must be a table")
    if not isinstance(tool, dict) or "agentgauge" not in tool:
        # A pyproject.toml with no [tool.agentgauge] table contributed
        # nothing, so naming it as the config source would be misleading.
        source = None

    unknown = sorted(set(table) - _KNOWN_KEYS)
    if unknown:
        raise ConfigError(
            f"[tool.agentgauge] unknown key(s) "
            f"{', '.join(repr(u) for u in unknown)}; valid keys are "
            f"{', '.join(sorted(_KNOWN_KEYS))}"
        )

    min_score = table.get("min_score")
    # bool is a subclass of int in Python, so `min_score = true` would
    # otherwise silently become a threshold of 1.0.
    if min_score is not None and (
        isinstance(min_score, bool) or not isinstance(min_score, (int, float))
    ):
        raise ConfigError("[tool.agentgauge] 'min_score' must be a number")

    exclude = _as_str_tuple(table.get("exclude", []), "exclude")

    return Config(
        min_score=float(min_score) if min_score is not None else None,
        exclude=exclude,
        rules=_build_rule_config(table),
        source=source,
    )


def _discover_path(target: Path) -> Path | None:
    """Look for pyproject.toml next to the scan target: inside it if target
    is a directory, alongside it if target is a single file. No upward
    directory search -- predictable discovery beats "found a config
    somewhere above me" surprise, especially for a CI tool."""
    directory = target if target.is_dir() else target.parent
    candidate = directory / "pyproject.toml"
    return candidate if candidate.is_file() else None


def display_path(path: Path) -> str:
    """How a config file's location is named in output.

    Relative to the working directory when the file is under it, absolute
    otherwise. Both the reported config source and every ConfigError go
    through this: an absolute path in a CI log discloses the runner's (or a
    developer's) directory layout for no benefit, and it makes the same
    commit produce different output on different machines. os.path.abspath
    rather than Path.resolve() so a symlinked checkout is named the way the
    caller spelled it.
    """
    absolute = Path(os.path.abspath(path))
    try:
        return absolute.relative_to(Path(os.path.abspath(os.curdir))).as_posix()
    except ValueError:
        return absolute.as_posix()


def load_config(target: Path, explicit_path: Path | None = None) -> Config:
    """Load [tool.agentgauge] from an explicit path or by discovery next to
    `target`. Returns the all-defaults Config if nothing is found -- a
    missing config file is not an error, a malformed one is."""
    path = explicit_path if explicit_path is not None else _discover_path(target)
    if path is None:
        return Config()
    shown = display_path(path)
    if not path.is_file():
        raise ConfigError(f"config file not found: {shown}")
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {shown}: {exc}") from exc
    try:
        return _parse(data, source=shown)
    except ConfigError as exc:
        raise ConfigError(f"{shown}: {exc}") from exc
