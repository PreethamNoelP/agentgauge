# Changelog

All notable changes to agentgauge are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [semantic versioning](https://semver.org/). For a
scanner, "breaking" includes anything that can change a repository's score
or verdict, since that is what CI gates on — those are called out
explicitly.

## [Unreleased]

### Fixed — the verdict (this changes CI outcomes)

- **A scan with zero applicable sites reported `PASS`.** Every category
  scores full marks when it never applied, so a repository agentgauge
  recognized nothing in scored exactly 100.0/100 and exited `0` — even
  under `--min-score 100 --fail-on-incomplete`, the strictest invocation
  available. The verdict is now `INCOMPLETE`, which `--fail-on-incomplete`
  turns into a red build.

  Two realistic routes reached this without any hostile intent: an agent
  codebase built on an SDK whose sinks are not in our tables, and an
  `exclude` pattern that happened to cover the only file that mattered.
  The second was the more serious one — `disabled_rules` had already been
  blocked from neutering the gate, but `exclude` could still do it, and
  excluding the deliberately-vulnerable fixture (44 findings,
  `FAIL_CRITICAL`) produced a clean 100.0/100 `PASS`.

  **This can change an existing pipeline from green to red**, and where it
  does, the previous green was not meaningful. If a repository genuinely
  has no agent tool-calling code, drop `--fail-on-incomplete` for it rather
  than treating 100/100 as a governance result.

### Added

- Excluded files are counted and reported: `excluded` in JSON and SARIF, an
  `EXCLUDED BY CONFIG` line in the human report, and a stderr warning.
  Config exclusions do **not** by themselves make a scan `INCOMPLETE` —
  excluding files is a project decision, not a coverage gap — but the
  report no longer hides that they happened.
- `APPLICABLE SITES` is printed next to the governance score. A 100.0 over
  0 sites and a 100.0 over 200 are the same number and entirely different
  claims; the denominator is no longer invisible in the human output.
- A GitHub composite action (`action.yml`) and a pre-commit hook
  (`.pre-commit-hooks.yaml`). The action installs from its own checkout, so
  the version that runs is exactly the ref the caller pinned. A single
  action run both gates the build and writes SARIF, because SARIF output
  already carries the governance exit code.

### Changed

- `mypy --strict` and `ruff` now gate CI, and the package is clean under
  both. agentgauge ships a `py.typed` marker; that marker was previously an
  unverified claim, and `mypy --strict` reported 31 errors against it —
  including two real type mismatches where a `set[str]` was passed to a
  parameter declared `frozenset[str]`.
- Rule vocabulary tables (`LOG_TOKENS`, `VALIDATION_TOKENS`,
  `RISKY_PARAM_TOKENS`, `DANGEROUS_WHEN_TRUE`/`_FALSE`, `CRITICAL_LABELS`,
  `_EXIT_CALLS`) are `frozenset`s. They are module-level constants that
  nothing should mutate, and it makes the set-union types line up.
- Removed a dead `hasattr(ast, "TryStar")` compatibility branch: `TryStar`
  has existed since 3.11, which is this package's floor.
- CI's self-scan gate no longer asserts `--min-score 100
  --fail-on-incomplete` on agentgauge's own source. That gate passed for a
  reason it did not advertise — agentgauge's own source has zero sites, so
  it was asserting arithmetic over an empty set. It now asserts what is
  actually true (no findings, nothing skipped), the clean fixture carries
  the "scores 100 against 24 real sites" claim, and a new gate pins that a
  scan recognizing nothing cannot report `PASS`.

### Performance

- ~15% faster scans, with byte-identical findings, score and verdict.
  `build_import_aliases` made two full `ast.walk` passes over every file
  and now makes one (imports are collected and assignments set aside in the
  same pass, preserving the document-order resolution a rebinding chain
  depends on); `functions` and `sensitive_calls` each walked the whole tree
  and now share a single pass. Measured best-of-5 on a 517-file / 77k-LOC
  corpus: 1.99 s → 1.69 s.
- `RULES.md`'s performance table is re-measured and now states its method.
  The previous figures (~25 s for 123k LOC, ~57 s for a 960-file stdlib
  tree) were roughly 6× high: that workload is millions of tiny `ast.walk`
  calls, which is precisely what a deterministic profiler over-charges.
  The 960-file tree is ~13 s.

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
- An `if`/`while`/`assert` test containing an unrelated call with a
  keyword argument spelled like the approval vocabulary
  (`if configure(require_approval=False):`) satisfied the human-oversight
  rule, because the test-walk picked up keyword-argument names along with
  real identifiers. The bare-statement form of this shape was already
  caught; only the `if`-wrapped form was not. Test expressions now only
  match a directly-referenced name or attribute, not a keyword name.
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
