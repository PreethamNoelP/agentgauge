"""File-walking scanner: bridge from a path on disk to a ScanReport.

Finds .py files under a root (or accepts a single file), parses each into
a FileContext, and streams them to the scoring aggregator one at a time --
memory stays flat regardless of repo size. Unparseable files are recorded
in report.skipped rather than aborting the scan -- a skipped file
contributes nothing to the score, in either direction.
"""

import tokenize
from pathlib import Path

from agentgauge.astutils import FileContext
from agentgauge.scoring import ScanReport, score_contexts

# Directories whose contents are never the user's own tool code. Scanning
# your own .venv is the classic way to drown a report in library noise.
SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", ".eggs",
    ".venv", "venv", "env", "node_modules", "site-packages",
    "build", "dist",
}


def iter_python_files(root: Path):
    """Yield .py files under root in sorted (deterministic) order,
    or root itself if it is a single file."""
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def scan(target: str | Path) -> ScanReport:
    root = Path(target)
    skipped: list[str] = []

    def iter_contexts():
        for path in iter_python_files(root):
            rel = path.name if root.is_file() else path.relative_to(root).as_posix()
            try:
                # tokenize.open honors PEP 263 coding declarations that plain
                # utf-8 open() would crash on.
                with tokenize.open(path) as fh:
                    source = fh.read()
                ctx = FileContext.from_source(source, path=rel)
            except SyntaxError as exc:
                skipped.append(f"{rel}: syntax error at line {exc.lineno}")
            except RecursionError:
                skipped.append(f"{rel}: too deeply nested to parse")
            except (OSError, UnicodeDecodeError) as exc:
                skipped.append(f"{rel}: unreadable ({exc})")
            else:
                yield ctx

    report = score_contexts(iter_contexts())
    report.skipped = skipped
    return report
