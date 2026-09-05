"""The browser playground (docs/) vendors a copy of every stdlib-only
agentgauge module it needs, since it's a static site with no build step
(see docs/README.md). These tests pin those copies to the real package so
a change that isn't mirrored fails here instead of silently making the
live demo misrepresent what it's running."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOT = REPO_ROOT / "agentgauge"
VENDOR_ROOT = REPO_ROOT / "docs" / "vendor" / "agentgauge"

VENDORED_FILES = [
    "__init__.py",
    "astutils.py",
    "config.py",
    "models.py",
    "scoring.py",
    "sarif.py",
    "rules/__init__.py",
    "rules/oversight.py",
    "rules/audit.py",
    "rules/ratelimit.py",
    "rules/errorhandling.py",
    "rules/validation.py",
    "rules/defaults.py",
]


@pytest.mark.parametrize("relpath", VENDORED_FILES)
def test_vendored_copy_matches_source(relpath):
    source_file = SOURCE_ROOT / relpath
    vendor_file = VENDOR_ROOT / relpath
    assert source_file.is_file(), f"missing source file: {source_file}"
    assert vendor_file.is_file(), (
        f"missing vendored copy: {vendor_file} -- see docs/README.md to refresh"
    )
    assert source_file.read_bytes() == vendor_file.read_bytes(), (
        f"{vendor_file} has drifted from {source_file} -- refresh the vendored "
        "copy (see docs/README.md) so the playground scans with the same code "
        "as the CLI"
    )


def test_no_filesystem_coupled_modules_are_vendored():
    # cli.py / scanner.py / __main__.py touch the real filesystem (file
    # walking, symlink checks, tokenize.open) and are unneeded by the
    # playground, which calls FileContext.from_source() directly. Vendoring
    # them would be dead weight at best and misleading at worst.
    for name in ("cli.py", "scanner.py", "__main__.py"):
        assert not (VENDOR_ROOT / name).exists()
