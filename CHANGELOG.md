# Changelog

All notable changes to agentgauge are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [semantic versioning](https://semver.org/). For a
scanner, "breaking" includes anything that can change a repository's score
or verdict, since that is what CI gates on — those are called out
explicitly.

## [Unreleased]

### Fixed — detection (these change scores)

- `from subprocess import run; run(cmd, shell=True)`, and every other plain
  `from X import y` sink call, was invisible: the local binding resolved
  only to a bare name, which the suffix table excludes as too generic.
  Such files previously scored 100/100.
- Method calls on a dynamic receiver (`Path(p).unlink()`,
  `clients[key].charge()`) were invisible, because dotted-name resolution
  gave up at the receiver even though the suffix table is
  receiver-agnostic by design.
- The human-oversight rule looked for approval vocabulary anywhere in the
  enclosing subtree, so a module-level sink was satisfied by any unrelated
  function in the same file that mentioned approval — silencing
  `FAIL_CRITICAL`. The signal must now share the call's execution scope.
- New sinks: `pathlib` deletion (`unlink`, `rmdir`), `asyncio`
  subprocesses, the `os.exec*` / `os.spawn*` family,
  `subprocess.getoutput` / `getstatusoutput`, unsafe deserialization
  (`pickle`, `marshal`, `dill`, `yaml.unsafe_load`), bulk remote deletion
  (`delete_bucket`, `delete_many`, `drop_table`, `terminate_instances`),
  and more payment APIs. `yaml.load` is deliberately *not* flagged: the
  `SafeLoader` form is safe and far too common for a critical gate.
- Vocabulary matching is alias-aware in the audit, validation and
  error-handling rules, so `from telemetry import audit_log as al`,
  `from utils import sanitize as scrub` and `import sys as s; s.exit()` no
  longer penalize code that is doing the right thing.
- Permissive defaults now reads string-keyed dict entries:
  `SERVER = {"auto_approve": True}` is the same decision as
  `auto_approve = True`.

### Fixed — the critical gate

- `disabled_rules = ["human-oversight"]` removed the only rule producing
  critical findings, so an ungated `shutil.rmtree` reported `PASS` and
  exited 0. Such a scan is now `INCOMPLETE`, with a warning, and reports
  `critical_gate_active: false`.
- `# agentgauge: ignore[]` and `# agentgauge: ignore[bad id!]` failed to
  match the bracketed form of the marker, fell back to the bare `ignore`
  form, and silently suppressed *every* rule on the line. A malformed
  marker now suppresses nothing and is reported.
- `extra_approval_markers = ["e"]` made every call name containing an "e"
  count as an approval check. Vocabulary entries must now be at least
  three characters.

### Fixed — scanning and paths

- Skip directories (`build`, `dist`, `venv`, …) were matched against
  absolute path components, so a checkout in `~/dev/build/` or
  `C:\...\dist\` skipped every file and exited 2.
- Exclude patterns used `fnmatch`, which normalizes case through
  `os.path.normcase` — the same config excluded different files on Windows
  than on Linux. Now `fnmatchcase`, with `**/`-prefixed, trailing-slash and
  bare-directory patterns behaving as documented.
- Findings were reported relative to the scan root, so `agentgauge src/`
  emitted `server.py` for `src/server.py` and no code-scanning dashboard
  could resolve the SARIF result. Paths are now relative to the working
  directory when the file is under it.
- Sources with NUL bytes, unknown PEP 263 encodings, or a size past
  `MAX_FILE_BYTES` (5 MB) are skipped rather than ending the scan.
- Skip reasons no longer embed absolute paths, so the same commit produces
  the same report on every machine. Neither does the reported config source:
  `config_source` in JSON and in the SARIF invocation, and every
  `ConfigError` message, now name the file relative to the working directory
  when it is under it.
- Symlinks pointing outside the scan root are no longer followed. A scanned
  repository is untrusted, and a `*.py` file that is really a link to
  `~/.aws/credentials` should not be read. In-tree symlinks are still
  followed; a refusal is reported, so it shows up as `INCOMPLETE` rather
  than as silently reduced coverage.

### Added

- `--version`.
- `--fail-on-incomplete`: exit 1 on an `INCOMPLETE` verdict. Previously a
  file that failed to parse shrank coverage while CI stayed green.
- The config file in effect is reported in the human output, in JSON
  (`config_source`) and in the SARIF invocation. Discovery deliberately
  does not search upwards, which made an ignored `[tool.agentgauge]` table
  invisible.
- `warnings` in the report: malformed and ineffective suppressions,
  disabled gate rules, and scans where no category had a single applicable
  site (`total_sites: 0`, where 100/100 means "nothing to check", not
  "well governed").
- SARIF: driver version, rule indices, and an `invocations` record carrying
  skipped files and scan warnings, which a results-only view dropped
  entirely.
- `py.typed` marker, for third-party rules written against `FileContext`.
- `.github/dependabot.yml`, and CI actions pinned to commit SHAs rather than
  movable major tags, with `permissions: contents: read` declared at the top
  of the workflow instead of inherited from a repository setting.

### Changed

- Unrecognized `[tool.agentgauge]` keys and unknown ids in
  `disabled_rules` are errors (exit 2) instead of silent no-ops.
- `min_score = true` is rejected; it previously became a threshold of 1.0.
- Control characters from scanned input are escaped before printing.
- A closed stdout pipe (`agentgauge . --json | head`) no longer raises
  `BrokenPipeError` over the exit code.
- Finding order includes rule and message, so two findings on one line
  cannot swap places between runs of the same commit.
- `is_tool_function` was split: `has_tool_decorator` is the decorator half,
  and `FileContext.tool_functions` is the cached whole-file answer rules
  should use. `FileContext.parents` is now a lazily built property rather
  than a constructor argument.
- Performance: 123k LOC of dense tool code, 59s to 25s; CPython's own
  stdlib (960 files), 64s to 57s.

## [0.1.0]

First release: six weighted governance categories, site-based scoring, the
`PASS` / `FAIL_CRITICAL` / `INCOMPLETE` verdict, `[tool.agentgauge]`
configuration, inline suppression, import-alias resolution, and JSON and
SARIF 2.1.0 output.
