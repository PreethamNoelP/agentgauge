"""File-walking scanner: bridge from a path on disk to a ScanReport.

Finds .py files under a root (or accepts a single file), parses each into
a FileContext, and streams them to the scoring aggregator one at a time --
memory stays flat regardless of repo size. Unparseable files are recorded
in report.skipped rather than aborting the scan -- a skipped file
contributes nothing to the score, in either direction, and makes the
verdict INCOMPLETE so a partial view never looks like a full pass.
"""

import fnmatch
import os
import tokenize
from pathlib import Path

from agentgauge.astutils import FileContext
from agentgauge.config import Config
from agentgauge.scoring import ScanReport, score_contexts

# Directories whose contents are never the user's own tool code. Scanning
# your own .venv is the classic way to drown a report in library noise.
# Matched against the path *relative to the scan root* only: matching
# absolute path components instead meant a repo that happened to live in
# ~/dev/build/ or C:\...\dist\ had every one of its files skipped.
SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", ".eggs",
    ".venv", "venv", "env", "node_modules", "site-packages",
    "build", "dist",
}

# Guard against a single pathological file exhausting CI memory: ast.parse
# builds a tree many times the size of its source, so a hostile
# multi-hundred-megabyte "module" is a cheap way to OOM a scanner that runs
# on untrusted repositories. No hand-written module comes close to this;
# anything over it is skipped visibly (INCOMPLETE), never silently.
MAX_FILE_BYTES = 5_000_000


def _match_variants(pattern: str) -> list[str]:
    """Spellings of an exclude pattern that should behave identically.

    A trailing slash is decoration ("vendor/" == "vendor"), and a leading
    "**/" is how people write "at any depth" -- but fnmatch reads it as
    "some characters, then a literal slash", so "**/generated_*.py" would
    match nothing at the repo root. Both spellings are normalized here
    rather than by translating patterns into regexes by hand.
    """
    pattern = pattern.rstrip("/") or pattern
    variants = [pattern]
    if pattern.startswith("**/"):
        variants.append(pattern[3:])
    return variants


def _is_excluded(rel_posix: str, patterns: tuple[str, ...]) -> bool:
    """Match an exclude pattern against the scan-relative posix path with
    gitignore-shaped semantics, using only fnmatch:

      - "tests/fixtures/*"  -- path match, as before
      - "**/generated_*.py" -- also matches at the root
      - "vendor" / "vendor/" -- the directory and everything under it
      - "*.gen.py"          -- a slash-free pattern matches the basename
                               at any depth

    fnmatchcase, not fnmatch: plain fnmatch normalizes case through
    os.path.normcase, which would make excludes case-insensitive on Windows
    and case-sensitive on Linux -- the same config producing different
    scans per platform.
    """
    parts = rel_posix.split("/")
    # The file itself, then each of its parent directories.
    candidates = [rel_posix] + ["/".join(parts[:i]) for i in range(1, len(parts))]
    for pattern in patterns:
        for variant in _match_variants(pattern):
            basename_only = "/" not in variant
            for candidate in candidates:
                if fnmatch.fnmatchcase(candidate, variant):
                    return True
                if basename_only and fnmatch.fnmatchcase(
                    candidate.rsplit("/", 1)[-1], variant
                ):
                    return True
    return False


def iter_python_files(root: Path, exclude: tuple[str, ...] = ()):
    """Yield .py files under root in sorted (deterministic) order,
    or root itself if it is a single file. An explicitly named file is
    always scanned -- exclude patterns filter a walk, they do not overrule
    the target the caller asked for."""
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if exclude and _is_excluded(rel.as_posix(), exclude):
            continue
        yield path


def _display_path(path: Path, root: Path, cwd: Path) -> str:
    """The path agentgauge reports for a finding.

    Relative to the current working directory whenever the file is under
    it, because that is the path a developer can click and -- more
    importantly -- the path GitHub/GitLab code scanning resolves a SARIF
    result against. Reporting root-relative paths meant `agentgauge src/`
    emitted "server.py" for src/server.py, which no code-scanning
    dashboard can map back to a file in the repository.

    os.path.abspath rather than Path.resolve(): a symlinked source tree
    should be reported under the path the caller used, not its target.
    """
    absolute = Path(os.path.abspath(path))
    try:
        return absolute.relative_to(cwd).as_posix()
    except ValueError:
        pass
    if root.is_file():
        return path.name
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _read_source(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(
            f"file is larger than the {MAX_FILE_BYTES // 1_000_000} MB scan limit"
        )
    # tokenize.open honors PEP 263 coding declarations that plain utf-8
    # open() would crash on.
    with tokenize.open(path) as fh:
        return fh.read()


def scan(target: str | Path, config: Config | None = None) -> ScanReport:
    root = Path(target)
    config = config if config is not None else Config()
    cwd = Path(os.path.abspath(os.curdir))
    skipped: list[str] = []

    def iter_contexts():
        for path in iter_python_files(root, config.exclude):
            rel = _display_path(path, root, cwd)
            try:
                ctx = FileContext.from_source(
                    _read_source(path), path=rel, config=config.rules
                )
            except SyntaxError as exc:
                where = f" at line {exc.lineno}" if exc.lineno else ""
                skipped.append(f"{rel}: syntax error{where} ({exc.msg})")
            except RecursionError:
                skipped.append(f"{rel}: too deeply nested to parse")
            except MemoryError:
                skipped.append(f"{rel}: ran out of memory while parsing")
            # ValueError: source containing NUL bytes (and the size guard
            # above). LookupError: a PEP 263 declaration naming an encoding
            # this interpreter does not have. Both are reachable from any
            # untrusted repository and neither should end the scan.
            except (OSError, UnicodeDecodeError, ValueError, LookupError) as exc:
                skipped.append(f"{rel}: unreadable ({exc})")
            else:
                yield ctx

    report = score_contexts(iter_contexts(), disabled_rules=config.rules.disabled_rules)
    report.skipped = skipped
    return report
