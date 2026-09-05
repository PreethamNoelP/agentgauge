# agentgauge rules

Every rule is a *heuristic*: a cheap, static approximation of a governance
property that really requires understanding runtime behavior. This document
states each heuristic precisely — including what it will **not** catch — so
you can decide how much to trust a finding or a pass.

## Scoring model

Each rule reports, per scan:

- **sites** — the number of places the rule applied
- **passed** — how many of those places were compliant
- **findings** — one entry per failing site, with a location and a fix

Category points = `weight × passed / sites`. Consequences:

1. **Zero sites → full marks.** A rule that never applied cannot be failed.
   A repo with no payment calls doesn't lose oversight points for payments.
2. **Zero evidence → no score at all.** If a scan finds zero Python files
   (typo'd path, pure-JS repo, everything unparseable), the CLI refuses to
   print a score and exits `2`. A 100/100 earned by looking at nothing must
   never look like a passing grade in CI.
3. **Zero *sites* → a score you should read carefully.** A repo with files
   but no sensitive calls, tool functions or governance flags scores
   100/100 by rule 1, six times over. That is the correct arithmetic and a
   misleading headline, so the report says so: `total_sites: 0` in JSON, and
   a warning on stderr — *"this score reflects the absence of anything to
   check, not evidence of governance."* Treat it as "agentgauge found no
   agent tool-calling code here", not as a clean bill of health.
4. **Averaging can't buy back a critical miss** (*critical-site
   dilution*, the name used for this in code comments). The score is an average
   across sites, so one catastrophic site can be diluted by many compliant
   ones — 99 fully-governed payment tools plus 1 with no approval check
   still average to 99.75/100. `ScanReport.verdict` is the independent gate:
   any human-oversight finding on a critical sink (`payment`, `file delete`,
   `shell exec`, `code exec`, `remote delete` — see `astutils.is_critical`)
   sets `FAIL_CRITICAL`, which fails CI regardless of `--min-score` or how
   high the aggregate score is.
5. **A partial or gate-less scan is not a PASS.** `INCOMPLETE` means either
   a file couldn't be parsed, or config disabled a rule the gate depends on
   (see *Configuration*). Either way agentgauge did not see everything it
   claims to cover. `INCOMPLETE` exits 0 by default; pass
   `--fail-on-incomplete` to make CI treat reduced coverage as a failure.

| Category | Weight | Sites are... | Evidence is... |
|---|---|---|---|
| Human oversight | 25 | sensitive calls | vocabulary in an enforcing position |
| Audit logging | 20 | tool functions | vocabulary |
| Rate limiting | 15 | tool functions | vocabulary |
| Error handling | 15 | `while True` loops + sensitive calls | AST structure |
| Tool scope & input validation | 15 | risky params of tool functions | vocabulary + annotations |
| Permissive defaults | 10 | governance-flag bindings | literal values |

### How much should you trust the number?

Read that last column before putting a threshold on the score. Only rule 4
proves anything structurally; rule 6 reads literal values, which is nearly
as solid. Rules 2, 3 and 5 — 50 of the 100 points — are asking whether
governance *vocabulary* appears near a tool function. A file that mentions
`rate_limiter` without using it, or calls `logger.info("hi")` and nothing
else, scores exactly as well as one that does the job properly.

That is a real ceiling on what the score means, and it is why agentgauge
produces a verdict as well as a number:

- **The verdict is the load-bearing output.** `FAIL_CRITICAL` says
  agentgauge found a specific catastrophic action with no approval gate in
  its own scope. That is a concrete claim about a concrete line, and it is
  what belongs in a CI gate.
- **The score is a trend line, not an audit result.** It is useful for
  "is this getting better or worse", for comparing modules, and for setting
  a floor a team agrees on. It is not evidence that a codebase is governed,
  and a 100/100 is not a certification. Nothing here replaces reading the
  code.
- **The weights are considered judgement, not calibration.** 25/20/15/15/
  15/10 reflects how much each control matters when it is missing entirely;
  no dataset was used to fit them. They are stable so that scores are
  comparable over time, not because they are provably right.

## Shared machinery

**Sensitive calls** are detected by two tables in `agentgauge/astutils.py`:

- `SENSITIVE_EXACT` — full dotted names: `os.system`, `subprocess.run`,
  `subprocess.getoutput`, the `os.exec*`/`os.spawn*` family,
  `asyncio.create_subprocess_shell`, `shutil.rmtree`, `os.remove`,
  `eval`/`exec`, `pickle.loads`, `marshal.loads`, `yaml.unsafe_load`,
  `requests.delete`, `httpx.delete`, …
- `SENSITIVE_SUFFIX` — method names distinctive enough to flag on *any*
  receiver: `.rmtree()`, `.unlink()`, `.rmdir()`, `.check_output()`,
  `.create_subprocess_exec()`, `.delete_bucket()`, `.delete_many()`,
  `.drop_table()`, `.terminate_instances()`, `.charge()`,
  `.transfer_funds()`, `.create_payment_intent()`, …

Generic suffixes (`run`, `call`, `delete`, `drop`, `send`, `system`) are
deliberately excluded: a false positive on a critical sink fails someone's
build for no reason, which costs more trust than a missed finding.

Two deliberate non-entries worth naming:

- **`yaml.load`** is not a sink. `yaml.load(s, Loader=SafeLoader)` is safe
  and ubiquitous; flagging it would make `FAIL_CRITICAL` untrustworthy.
  `yaml.unsafe_load` names its own risk and is flagged.
- **`open(path, "w")`** is not a sink. Truncating a file is destructive, but
  the pattern is far too common to gate a build on.

**Tool functions** — the site population for rules 2, 3, and 5 — are
functions decorated with a `*tool*` decorator (`@mcp.tool()`, `@tool`,
`@app.tool`) or containing a sensitive call anywhere in their body,
including inside a nested `def` (a factory that hands a sink to an inner
function is still what exposes it).

**Name resolution.** A call is resolved to its canonical dotted name
through a per-file alias map (`build_import_aliases`) covering:

| Written as | Resolves to |
|---|---|
| `import subprocess as sp; sp.run(c)` | `subprocess.run` |
| `from shutil import rmtree as rt; rt(p)` | `shutil.rmtree` |
| `from subprocess import run; run(c)` | `subprocess.run` |
| `from os import system; system(c)` | `os.system` |
| `rm = shutil.rmtree; rm(p)` | `shutil.rmtree` |
| `import subprocess as sp; run = sp.run; run(c)` | `subprocess.run` |
| `Path(p).unlink()` | suffix table only (dynamic receiver) |

Global limitations, inherited by every rule:

- **Dynamic calls:** `getattr(os, "remove")(p)`, `funcs["rm"](x)`,
  `eval("os.remove")(p)` are invisible to any static name-based scan.
- **Deeper indirection:** one hop of rebinding is resolved
  (`rm = shutil.rmtree`); two are not (`a = shutil.rmtree; b = a; b(p)`).
  Neither is a sink reached through a function's return value
  (`get_deleter()(p)`).
- **Scope-blind aliasing:** the alias map is one flat table per file, so a
  local variable shadowing an imported name still resolves to the import.
  This can produce a false positive: `from os import remove` followed by a
  local `remove = items.pop` would report a `file delete` at `remove(0)`.
  Rare enough to be worth the coverage; report it if you hit it.
- **Star imports:** `from subprocess import *` binds names we cannot
  enumerate, so calls through it are missed.
- **Single-file analysis:** every rule sees one file at a time. A sink in
  `a.py` gated by an approval helper called from `b.py` is a false failure
  (see rule 1); no cross-module data flow is attempted.
- **Python only:** governance settings living in JSON/YAML/env config are
  not seen (see rule 6).
- **Vocabulary is extensible, not overridable:** every keyword list below
  can be *added to* per project via `[tool.agentgauge]` in pyproject.toml
  (see "Configuration") — never replaced. A team can teach a rule a new
  word; it can't make a rule stop recognizing the built-in ones.

## Rule 1 — Human oversight (`human-oversight`, 25 pts)

**Heuristic:** every sensitive call must have approval *vocabulary*
(`approv`, `confirm`, `consent`, `authoriz`, `human`, or builtin `input()`)
in an **enforcing position** within its **own execution scope**.

*Enforcing position* means: the identifier is the callee of a call, appears
in the test of an `if`/`while`/`assert`, or names a decorator on the
enclosing function. A bare assignment or a keyword argument passed to an
unrelated call does not count — those are never enforcing.

*Own execution scope* means the nearest enclosing `def`/`async def`, not
including nested `def` bodies; or, for a call outside any function, the
module's top level plus class bodies (which also execute there). A check
written inside some other function does not run when this call does, so it
cannot satisfy it.

- **Catches:** sensitive calls in functions with zero approval machinery —
  the auto-executing agent tool. Also the dead-variable and
  wrong-keyword-argument shapes, and module-level sinks in files that
  happen to contain an approval-flavored helper elsewhere.
- **False passes:** position ≠ correctness. `if approved: rmtree(path)`
  passes even when `approved = True` is hardcoded two lines above with no
  real check behind it — confirming the *position* is enforcing, not that
  the tested value's truth ever came from an actual approval. Vocabulary is
  matched as a substring, so an unrelated `is_human_readable()` call also
  satisfies the rule. Both would need data-flow analysis to close, which is
  out of scope for a static heuristic.
- **False failures:** approval enforced in a helper this function calls, or
  in a shared middleware layer, or in another module. Teams using
  vocabulary we don't know ("vet", "greenlight") — extend it via config.
  A wrapper (`def _rm(p): shutil.rmtree(p)`) is flagged at its own
  definition even when every caller gates it; that is the conservative
  direction on purpose, and inline suppression is the intended escape.
- **Configurable:** `extra_approval_markers` adds to the built-in stems.

## Rule 2 — Audit logging (`audit-logging`, 20 pts)

**Heuristic:** every tool function must contain a call whose dotted name
has a `log`/`logger`/`logging`/`audit` **token** (split on `.` and `_`) —
so `logger.info` and `audit_log` count, `login()` does not. Alias-aware, so
`from telemetry import audit_log as al; al(...)` counts.

- **Catches:** tool functions with no logging call at all.
- **False passes:** any log call counts, however useless
  (`logger.info("hi")`); we can't verify actor/action/args are recorded.
  Any function with a log-like name counts, even `delete_logs()`. A log
  call inside a nested `def` counts for the enclosing function too.
- **False failures:** logging inside shared wrappers/middleware; tools
  registered without decorators (`server.add_tool(fetch)`) that contain no
  sensitive call are not sites at all.
- **Configurable:** `extra_log_tokens` adds project-specific vocabulary
  (e.g. a team's `telemetry.record(...)` wrapper).

## Rule 3 — Rate limiting (`rate-limiting`, 15 pts)

**Heuristic:** every tool function must reference rate-limit vocabulary in
its body or decorators: an identifier containing `ratelimit`, `throttle`,
or `limiter` (underscores ignored), or the `ratelimit` library's `@limits`
decorator. Bare `limit` deliberately does **not** count (pagination, SQL).

- **Catches:** tool functions with no limiting anywhere in sight.
- **False passes:** vocabulary presence, not enforcement — a dead
  `rate_limiter = None` passes, a misconfigured limiter passes, and a
  function *named* `throttle_writes` passes trivially.
- **False failures:** limiting done at infrastructure level (API gateway,
  middleware, global semaphore elsewhere). Repos doing it right at the
  infra layer will systematically under-score, unless...
- **Configurable:** `assume_external_rate_limiting = true` zeroes out this
  category's sites entirely for gateway-fronted deployments — the category
  scores full marks the same way it does when no tool functions exist at
  all (see "Zero sites → full marks" above). `extra_rate_limit_markers`
  adds project-specific vocabulary.

## Rule 4 — Error handling (`error-handling`, 15 pts)

**Heuristic:** two site types. (a) Every unconditional loop
(`while True:`, `while 1:`) must contain an exit that actually leaves it —
a `break` at *this* loop's level (a `break` in a nested loop exits only
the inner one), a `return`/`raise` not inside a nested `def`, or
`sys.exit`. (b) Every sensitive call must sit in the **body** of a `try` —
handlers, `else`, and `finally` don't count, because code there is not
protected by that try. `try`/`except*` counts the same as `try`/`except`.

- **Catches:** exit-free polling loops (the runaway-agent shape) and naked
  sensitive calls — including breaks-in-nested-loops and
  calls-inside-except-handlers that naive checks bless.
- **False passes:** unreachable exits (`if False: break`); a `raise`
  caught by a try inside the same loop; `except: pass` counts as handled
  even though swallowing errors is its own smell.
- **Won't catch:** semantically infinite loops (`while not done:` where
  `done` never changes), infinite recursion, unbounded generators,
  `for _ in itertools.count()`. Termination is undecidable; our line is
  "syntactically unconditional loops only".

## Rule 5 — Tool scope & input validation (`input-validation`, 15 pts)

**Heuristic:** parameters of tool functions whose name, split into lowercase
tokens on `.`/`_` (the same token mechanism rule 2 uses), has one exactly
equal to a risky token (`path`, `file`, `dir`, `cmd`, `command`, `query`,
`sql`, `url`, `host`, `target`, ...) must be referenced by a validation
construct in the function: an `if`/`while`/`assert` test mentioning the
parameter, or a call with validation vocabulary (`validate*`, `sanitize`,
`check*`, `shlex.quote`, allowlist names) receiving it. Alias-aware on the
validator side.

- **Catches:** the canonical MCP hole — `path`/`cmd`/`query` flowing
  straight into `open()`/`subprocess`/a DB.
- **False passes:** any `if` mentioning the param counts (`if path:` is a
  truthiness check, not validation); validation *after* use passes; a
  parameter merely mentioned in an unrelated conditional passes.
- **False failures / blind spots:** validators we don't recognize by name
  (`normalize(path)`). A risky value in a param named `p` is invisible.
  So is one whose risky word isn't its own token: token matching splits
  only on `.`/`_`, so a concatenated or camelCase name — `filePath`,
  `sqlQuery`, `cmdline` — never produces a token that exactly equals
  `path`/`sql`/`cmd`, and the parameter is skipped entirely rather than
  flagged. Prefer `file_path` / `sql_query` / `cmd_line` if you want this
  rule to see the parameter at all. Inputs arriving as a Pydantic model
  field rather than a parameter are not seen at all — a real gap for
  FastMCP servers that declare a schema class.
- **Type-annotation evidence:** `Literal["a", "b"]` (a closed set of
  allowed values) and `Annotated[T, Field(...)]` (the FastMCP/Pydantic
  idiom for declaring pattern/length/range constraints) both count as
  validation — the presence of the construct is the proof, exactly like
  rule 6 trusts a boolean literal without tracing where it came from. This
  only checks that a `Field(...)` call appears in the annotation's
  metadata, not what constraints it declares — `Annotated[str, Field()]`
  with no arguments at all still counts, the same way any recognized
  validator call counts regardless of whether its logic is correct.
- **Configurable:** `extra_risky_params` and `extra_validation_tokens` add
  project-specific vocabulary on either side of the check.

## Rule 6 — Permissive defaults (`permissive-defaults`, 10 pts)

**Heuristic:** inverted category — sites exist only where a governance
knob appears. Every binding of a recognized flag name to a boolean
constant is judged: dangerous-when-True flags (`auto_approve`,
`skip_confirmation`, `allow_all`, `bypass_safety`, ...) must be `False`;
dangerous-when-False flags (`require_approval`, `human_in_the_loop`,
`verify`, `safe_mode`, `sandbox`, ...) must be `True`. Names are matched
case-insensitively with underscores and hyphens stripped, so
`auto_approve`, `AUTO_APPROVE` and `autoApprove` are one flag.

Bindings recognized: assignments (including attribute targets and
annotated assignments), keyword arguments, function-parameter defaults, and
dict entries with a literal string key — `SERVER = {"auto_approve": True}`
is the same decision as `auto_approve = True`, and is how a Python MCP
server usually spells its settings.

- **Catches:** permissive booleans wherever Python can spell them,
  including `requests.get(url, verify=False)`.
- **Not sites:** non-constant bindings (`require_approval = load_config()`)
  and non-literal dict keys — we don't guess at values we can't see.
- **False positives to know about:** the flag names are matched by name
  alone, with no idea of the surrounding library. `verify=False` on an
  internal helper that has nothing to do with TLS is still flagged, and
  `sandbox=False` in a payment SDK usually means "production", not
  "unsafe". Both are cheap to suppress inline; neither is critical.
- **Blind spots:** **non-Python config** — JSON/YAML/`.env`, which is where
  real deployments (e.g. `claude_desktop_config.json`) actually set these.
  A string value is never a site either: `AUTO_APPROVE = "true"` and
  `os.environ.get("AUTO_APPROVE", "true")` are both invisible.
- **Configurable:** `extra_dangerous_when_true` /
  `extra_dangerous_when_false` add project-specific flag names
  (`yolo_mode = True` no longer has to be a blind spot once it's named in
  config) — normalized the same way as the built-in lists.
- **Planned:** a config-file scanner scoped to known filenames — pure-data
  formats are *more* statically tractable than Python, so error rates will
  be lower than the AST rules.

## Cross-rule interactions

- `require_approval=False` **fails both rule 1 and rule 6**: it is not an
  enforcing position (rule 1), and it is the dangerous polarity of a
  recognized flag (rule 6). The two rules catch it for independent
  reasons — rule 1 because nothing gates on it, rule 6 because if
  something did, it would gate the wrong way.
- A sensitive call is a site in **both** rule 1 and rule 4 — oversight and
  error handling are independent obligations for the same action.
- Rules 2, 3, and 5 share the *tool function* population; a function
  containing a sensitive call is held to tool standards even without a
  `@tool` decorator.
- A sink inside a nested `def` makes **both** the inner and the outer
  function tool functions, so one sink can produce two audit-logging sites.
  This weights heavily-nested code slightly more; it is deliberate, since
  the outer function is what exposes the inner one.

## What agentgauge scans, and what it skips

`.py` files under the target, in sorted order. Skipped, with a note in
`report.skipped` (which makes the verdict `INCOMPLETE`):

- Directories named `.git`, `__pycache__`, `.venv`, `venv`, `env`,
  `node_modules`, `site-packages`, `build`, `dist`, and the usual caches —
  matched **relative to the scan root**, so a checkout that itself lives in
  a directory called `build/` is scanned normally.
- Files that fail to parse: syntax errors, NUL bytes, a PEP 263 coding
  declaration naming an unknown encoding, or nesting deep enough to exhaust
  the parser's stack.
- Files larger than `scanner.MAX_FILE_BYTES` (5 MB). `ast.parse` builds a
  tree many times the size of its source, and this tool runs on untrusted
  repositories; no hand-written module comes close to the limit.
- Symlinks whose target lies outside the scan root, or that cannot be
  resolved at all (a loop, a dangling target). A scanned repository is
  untrusted input, and a file named `config.py` that is really a link to
  `~/.aws/credentials` should not be read just because it matched `*.py`.
  Symlinks that stay *inside* the root are followed normally — a shared
  module linked into a package is ordinary repository layout. Symlinked
  *directories* were never traversed: pathlib's `**` does not descend into
  them, so a link cannot redirect the walk itself. An explicitly named
  target is always scanned, the same way exclude patterns don't overrule it.

Nothing under the target is ever imported, executed, or evaluated —
`ast.parse` and `tokenize` only.

**Note on coverage:** a file agentgauge cannot parse is a file it cannot
govern. That makes `INCOMPLETE` meaningful, and it is why
`--fail-on-incomplete` exists: a Python version difference or a generated
file can quietly shrink what CI is actually checking.

## Configuration

An optional `[tool.agentgauge]` table in `pyproject.toml` (or a file passed
via `--config`) tunes a scan without forking source. Every key defaults to
today's built-in behavior — a project with no config file scans identically
to one with an empty table.

```toml
[tool.agentgauge]
min_score = 80                              # default for --min-score
exclude = ["tests/fixtures/*", "**/generated_*.py", "vendor/"]
disabled_rules = ["rate-limiting"]          # category removed; max_score drops below 100
assume_external_rate_limiting = false       # true: rule 3 scores every scan full marks
extra_approval_markers = ["vet", "greenlight"]
extra_log_tokens = ["telemetry"]
extra_rate_limit_markers = ["throughput_cap"]
extra_validation_tokens = ["scrub"]
extra_risky_params = ["apikey", "secret"]
extra_dangerous_when_true = ["yolo_mode"]
extra_dangerous_when_false = ["least_privilege"]
```

**Validation is strict, on purpose.** For a governance gate, settings that
quietly differ from what the author wrote are the worst failure mode, so
these are usage errors (exit `2`), not no-ops:

- an unrecognized key (`excludes`, `min_scores`);
- an id in `disabled_rules` that names no rule (`rate_limiting` with an
  underscore) — the error lists the valid ids;
- a vocabulary entry shorter than three characters.
  `extra_approval_markers = ["e"]` would make every call name containing an
  "e" count as an approval check, switching off the critical gate from a
  config file;
- `min_score = true` — `bool` subclasses `int` in Python, so this used to
  become a threshold of `1.0`.

**Precedence.** `--min-score` on the command line overrides `min_score` in
config; an explicit `--config PATH` overrides discovery.

**Discovery** looks for `pyproject.toml` next to the scan target only
(inside it for a directory, alongside it for a single file) — no upward
directory search, so a scan's config source is always predictable, never
"found somewhere above me". This also keeps `exclude` patterns meaningful,
since they are relative to the scan root. The consequence is that
`agentgauge src/` does **not** pick up the repository root's config; to
make that visible rather than silent, the report names the config file it
applied (human output, `config_source` in JSON, the SARIF invocation), and
prints nothing there when no `[tool.agentgauge]` table was found.

**Exclude pattern semantics.** Matched case-sensitively on every platform
against the path relative to the scan root:

| Pattern | Matches |
|---|---|
| `tests/fixtures/*` | paths under that directory |
| `**/generated_*.py` | `generated_x.py` at any depth, including the root |
| `vendor` or `vendor/` | that directory and everything under it, at any depth |
| `*.gen.py` | any file with that basename, at any depth |

An explicitly named single-file target is always scanned: exclude patterns
filter a directory walk, they do not overrule the file you asked for.

An excluded file is not scanned at all, so its findings — **including
critical ones** — do not exist as far as the verdict is concerned. That is
the point of an exclude, and it is also the bluntest way to make this tool
say nothing. `files_scanned` and the applied config file are both in every
report; if you are reviewing someone else's `agentgauge` result, read their
`exclude` list first.

**`disabled_rules`** removes a category from the scan entirely — `max_score`
in the report drops below 100 rather than the remaining categories silently
renormalizing up to fill the gap. A `--min-score` threshold set for a full
100-point scan means less once a category is disabled; that tradeoff is the
caller's to make, not something agentgauge should hide.

**Disabling `human-oversight` cannot produce a `PASS`.** It is the only
rule that marks findings `critical`, so switching it off removes the
`FAIL_CRITICAL` gate rather than just a category. Such a scan reports
`INCOMPLETE` with an explicit warning and `critical_gate_active: false`.
It is deliberately *not* `FAIL_CRITICAL`: with the rule off, agentgauge
never looked for the sinks, so it has no finding to fail on and no honest
way to claim one. `--fail-on-incomplete` is how CI makes this red.

### Suppressing individual findings

`# agentgauge: ignore` on the same source line as a finding suppresses it;
`# agentgauge: ignore[human-oversight, error-handling]` suppresses only the
named rules on that line. Trailing free text is allowed as a reason. A
suppressed finding is removed from the report and its site is credited as
passed — matched against real COMMENT tokens (via `tokenize`), so a string
literal that happens to contain the marker text is never mistaken for one.

Suppression is treated as a security-sensitive feature, so:

- **A malformed marker suppresses nothing.** `# agentgauge: ignore[]` and
  `# agentgauge: ignore[bad id!]` are reported as warnings rather than
  silently falling back to the unqualified form. (They used to: the
  bracketed alternative failed to match, the bare `ignore` alternative won,
  and a narrow suppression became a blanket one covering every rule on the
  line — including rules added in future versions.)
- **A well-formed marker naming a rule that doesn't exist is reported too.**
  `# agentgauge: ignore[permissive-default]` suppresses nothing; a
  suppression that silently fails to work is nearly as bad as one that
  silently works too well.
- **A bare `ignore` followed by prose is malformed too.**
  `# agentgauge: ignore rate-limiting` (brackets forgotten) used to
  suppress every rule on the line. A free-text reason is fine, but it has
  to announce itself: `# agentgauge: ignore -- the gateway gates this`,
  or `:` / `#` as the delimiter. After a bracketed rule list, any trailing
  text is taken as a reason.
- **`# agentgauge: ignored in review` is not a marker either.** The word
  must stand alone.
- **Scope is exactly one line** — the line the finding is reported on. For a
  multi-line call, that is the line the call starts on.
- **An unqualified `# agentgauge: ignore` covers every rule, including ones
  added later.** Prefer the bracketed form in long-lived code.

**A suppression cannot buy back `FAIL_CRITICAL`.** Suppressing a finding on
a critical sink still forces the verdict, and the report says so explicitly
(`critical_suppressed` in JSON/SARIF, a CLI warning line). This is
deliberate: the entire reason `ScanReport.verdict` exists is that
score-averaging must never be able to hide one catastrophic miss behind a
hundred compliant sites — a one-line comment achieving the same outcome
would just be that problem wearing a suppression instead of an average.
Suppression is for decluttering noise on non-critical categories during
incremental adoption, not for silencing the one guarantee this tool makes.

To audit suppressions across a repo, grep for the marker: it is a plain
comment on purpose, so `git log -S'agentgauge: ignore'` works and code
review sees it in the diff.

### Output formats

`--json` emits agentgauge's own report shape. Its top-level and per-finding
keys are pinned by tests; new keys may be added, existing ones are not
renamed or removed without a major version.

`--sarif` emits SARIF 2.1.0 for ingestion by GitHub/GitLab code scanning
and most AppSec dashboards. `critical` findings map to SARIF `error`,
everything else to `warning`, mirroring the split the verdict uses. The log
also carries the driver version (so a dashboard can tell a detection change
from a code change) and an `invocations` record listing skipped files and
scan warnings — a results-only view would otherwise show a clean dashboard
for a scan that never read half the repo. The two flags are mutually
exclusive.

Result paths are relative to the working directory when the scanned file is
under it, which is what a code-scanning upload needs to resolve a result
back to a file in the repository. Run agentgauge from the repository root.

## Performance

Single-pass-per-question AST analysis, one file resident at a time, no I/O
beyond reading sources. Measured on this implementation:

| Corpus | Files | Time |
|---|---|---|
| 123k LOC of dense tool code | 600 | ~25 s |
| CPython's own standard library | 960 | ~57 s |
| A typical MCP server repo (a few thousand LOC) | tens | < 1 s |

Peak memory is a single file's AST — flat regardless of repo size.

Roughly 5,000 LOC/s is pure-Python-with-`ast` territory, not
compiled-linter territory: `ast.walk` is the whole cost, and six
independent rules each asking their own questions is the architecture's
price for being easy to extend. `FileContext` caches the views the rules
share (`functions`, `sensitive_calls`, `tool_functions`, `parents`), which
is what makes it 5,000 rather than 2,000 LOC/s. For a very large monorepo,
scope the scan with `exclude` or point it at the directories that actually
hold agent code.
