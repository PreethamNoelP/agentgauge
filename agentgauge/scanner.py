"""File-walking scanner: bridge from a path on disk to a ScanReport.

Finds .py files under a root (or accepts a single file), parses each into
a FileContext, and streams them to the scoring aggregator one at a time --
memory stays flat regardless of repo size. Unparseable files are recorded
in report.skipped rather than aborting the scan -- a skipped file
contributes nothing to the score, in either direction.
"""

import fnmatch
import tokenize
from pathlib import Path

from agentgauge.astutils import FileContext
from agentgauge.config import Config
from agentgauge.scoring import ScanReport, score_contexts

# Directories whose contents are never the user's own tool code. Scanning
# your own .venv is the classic way to drown a report in library noise.
SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", ".eggs",
    ".venv", "venv", "env", "node_modules", "site-packages",
    "build", "dist",
}


def _is_excluded(rel_posix: str, patterns: tuple[str, ...]) -> bool:
    """fnmatch against the scan-relative posix path, so a pattern like
    "tests/fixtures/*" or "**/generated_*.py" behaves the way a .gitignore-
    style glob reads, without pulling in a globbing dependency."""
    return any(fnmatch.fnmatch(rel_posix, pattern) for pattern in patterns)


def iter_python_files(root: Path, exclude: tuple[str, ...] = ()):
    """Yield .py files under root in sorted (deterministic) order,
    or root itself if it is a single file."""
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if exclude and _is_excluded(path.relative_to(root).as_posix(), exclude):
            continue
        yield path


def scan(target: str | Path, config: Config | None = None) -> ScanReport:
    root = Path(target)
    config = config if config is not None else Config()
    skipped: list[str] = []

    def iter_contexts():
        for path in iter_python_files(root, config.exclude):
            rel = path.name if root.is_file() else path.relative_to(root).as_posix()
            try:
                # tokenize.open honors PEP 263 coding declarations that plain
                # utf-8 open() would crash on.
                with tokenize.open(path) as fh:
                    source = fh.read()
                ctx = FileContext.from_source(source, path=rel, config=config.rules)
            except SyntaxError as exc:
                skipped.append(f"{rel}: syntax error at line {exc.lineno}")
            except RecursionError:
                skipped.append(f"{rel}: too deeply nested to parse")
            except (OSError, UnicodeDecodeError) as exc:
                skipped.append(f"{rel}: unreadable ({exc})")
            else:
                yield ctx

    report = score_contexts(iter_contexts(), disabled_rules=config.rules.disabled_rules)
    report.skipped = skipped
    return report
