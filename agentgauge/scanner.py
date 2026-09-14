"""File-walking scanner: bridge from a path on disk to a ScanReport.

Finds .py files under a root (or accepts a single file), parses each into
a FileContext, and streams them to the scoring aggregator one at a time --
memory stays flat regardless of repo size. Unparseable files are recorded
in report.skipped rather than aborting the scan -- a skipped file
contributes nothing to the score, in either direction, and makes the
verdict INCOMPLETE so a partial view never looks like a full pass.
"""

import os
import tokenize
from pathlib import Path
from typing import Callable, Iterator

from agentgauge import configscan
from agentgauge.astutils import FileContext
from agentgauge.config import Config
from agentgauge.fswalk import MAX_FILE_BYTES, SKIP_DIRS, is_excluded
from agentgauge.rules import defaults
from agentgauge.scoring import ScanReport, score_contexts

__all__ = [
    "MAX_FILE_BYTES", "SKIP_DIRS", "is_excluded",
    "iter_python_files", "escapes_scan_root", "scan",
]


def iter_python_files(
    root: Path,
    exclude: tuple[str, ...] = (),
    on_excluded: Callable[[Path], None] | None = None,
) -> Iterator[Path]:
    """Yield .py files under root in sorted (deterministic) order,
    or root itself if it is a single file. An explicitly named file is
    always scanned -- exclude patterns filter a walk, they do not overrule
    the target the caller asked for.

    `on_excluded` is called once per file an `exclude` pattern removed, so
    the report can say how much of the tree config kept it from seeing.
    SKIP_DIRS hits are deliberately not reported: those are built-in noise
    filters (.venv, node_modules) that every run applies identically, not a
    project decision a reader of the report needs to know about.
    """
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if exclude and is_excluded(rel.as_posix(), exclude):
            if on_excluded is not None:
                on_excluded(path)
            continue
        yield path


def escapes_scan_root(path: Path, root: Path) -> bool:
    """True if `path` is a symlink whose target lies outside `root`.

    Scanned repositories are untrusted. A file named `config.py` that is
    really a link to ~/.aws/credentials would otherwise be read and parsed,
    and while agentgauge never executes what it reads and never reports
    string values, identifier names from a file outside the tree could
    surface in the report under an in-tree path. Refusing to follow the link
    removes the question.

    Symlinks that stay *inside* the scan root are followed normally -- they
    are ordinary repository layout (a shared module linked into a package),
    and skipping them would silently shrink coverage.

    Only files are checked: pathlib's `**` does not descend into symlinked
    directories, so a link cannot redirect the walk itself.

    An unresolvable link -- a loop, or a target on a filesystem that errors
    -- counts as escaping. "Cannot prove it stays inside" is the same answer
    as "leaves" for this purpose.
    """
    if not path.is_symlink():
        return False
    try:
        # Both sides resolved, so a checkout that itself lives under a
        # symlink (/tmp -> /private/tmp on macOS) compares consistently.
        path.resolve(strict=True).relative_to(root.resolve())
    except (ValueError, OSError, RuntimeError):
        return True
    return False


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


def _relativize(reason: str, path: Path, rel: str) -> str:
    """Replace any spelling of the file's absolute path in an exception
    message with the reported relative one, so the same commit produces the
    same report on every machine."""
    for spelling in {str(path), os.path.abspath(path)}:
        reason = reason.replace(spelling, rel)
    return reason


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
    excluded = 0

    def count_excluded(_path: Path) -> None:
        nonlocal excluded
        excluded += 1

    def iter_contexts() -> Iterator[FileContext]:
        for path in iter_python_files(root, config.exclude, count_excluded):
            rel = _display_path(path, root, cwd)

            def note(reason: str) -> None:
                # Some exception messages (notably "unknown encoding for
                # <path>") embed the absolute path, which would make the
                # report differ between machines for the same commit. The
                # entry already names the file relatively.
                skipped.append(f"{rel}: {_relativize(reason, path, rel)}")

            # Checked here rather than in iter_python_files so the refusal is
            # reported rather than silent: a file we declined to read is a
            # hole in coverage, which is exactly what INCOMPLETE is for.
            # An explicitly named target is the caller's own choice and is
            # never second-guessed, the same way exclude patterns aren't
            # allowed to overrule it.
            if not root.is_file() and escapes_scan_root(path, root):
                note(
                    "symlink not followed (target is outside the scan root, "
                    "or could not be resolved)"
                )
                continue

            try:
                ctx = FileContext.from_source(
                    _read_source(path), path=rel, config=config.rules
                )
            except SyntaxError as exc:
                where = f" at line {exc.lineno}" if exc.lineno else ""
                note(f"syntax error{where} ({exc.msg})")
            except RecursionError:
                note("too deeply nested to parse")
            except MemoryError:
                note("ran out of memory while parsing")
            # ValueError: source containing NUL bytes (and the size guard
            # above). LookupError: a PEP 263 declaration naming an encoding
            # this interpreter does not have. Both are reachable from any
            # untrusted repository and neither should end the scan.
            except (OSError, UnicodeDecodeError, ValueError, LookupError) as exc:
                note(f"unreadable ({exc})")
            else:
                yield ctx

    report = score_contexts(iter_contexts(), disabled_rules=config.rules.disabled_rules)
    report.skipped = skipped

    # JSON config-file scanning (claude_desktop_config.json, mcp.json, ...):
    # the same governance question as the AST "Permissive defaults" rule,
    # merged into the same CategoryResult rather than a category of its
    # own -- see configscan.py's module docstring. Skipped entirely if that
    # rule was disabled: there is then no category to merge into, and a
    # disabled rule must mean "we didn't look", not "we looked and it's
    # fine" (the same reasoning score_contexts already applies to the AST
    # rule via CRITICAL_GATE_RULES/gate_disabled).
    defaults_category = next(
        (c for c in report.categories if c.name == defaults.CATEGORY), None
    )
    if defaults_category is not None:
        config_files_scanned = 0
        for path in configscan.iter_config_files(
            root, config.extra_config_filenames, config.exclude, count_excluded
        ):
            rel = _display_path(path, root, cwd)
            if not root.is_file() and escapes_scan_root(path, root):
                skipped.append(
                    f"{rel}: symlink not followed (target is outside the "
                    "scan root, or could not be resolved)"
                )
                continue
            sites, passed, findings, skip_reason = configscan.scan_config_file(
                path, rel, config.rules
            )
            if skip_reason is not None:
                skipped.append(f"{rel}: {_relativize(skip_reason, path, rel)}")
                continue
            config_files_scanned += 1
            defaults_category.sites += sites
            defaults_category.passed += passed
            defaults_category.findings.extend(findings)
        report.config_files_scanned = config_files_scanned

    # Assigned after both walks have finished, so the count is final. Unlike
    # `skipped` this does not make the verdict INCOMPLETE: excluding files
    # is a deliberate project decision, not a gap in coverage agentgauge hit
    # by accident. It only has to be *visible* -- and when an exclude
    # pattern does hide everything that mattered, the resulting zero-site
    # scan is INCOMPLETE on its own merits.
    report.excluded = excluded
    if excluded:
        report.warnings.append(
            f"{excluded} file(s) were not scanned because an 'exclude' pattern "
            "in the config matched them"
        )
    return report
