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

Category points = `weight × passed / sites`. Two consequences:

1. **Zero sites → full marks.** A rule that never applied cannot be failed.
   A repo with no payment calls doesn't lose oversight points for payments.
2. **Zero evidence → no score at all.** If a scan finds zero Python files
   (typo'd path, pure-JS repo, everything unparseable), the CLI refuses to
   print a score and exits `2`. A 100/100 earned by looking at nothing must
   never look like a passing grade in CI.
3. **Averaging can't buy back a critical miss.** The score is an average
   across sites, so one catastrophic site can be diluted by many compliant
   ones — 99 fully-governed payment tools plus 1 with no approval check
   still average to 99.75/100. `ScanReport.verdict` is the independent gate:
   any human-oversight finding on a critical sink (`payment`, `file delete`,
   `shell exec`, `code exec`, `remote delete` — see `astutils.is_critical`)
   sets `FAIL_CRITICAL`, which fails CI regardless of `--min-score` or how
   high the aggregate score is. `INCOMPLETE` means a file couldn't be
   parsed, so a clean result over a partial view isn't a full pass either.

| Category | Weight | Sites are... |
|---|---|---|
| Human oversight | 25 | sensitive calls |
| Audit logging | 20 | tool functions |
| Rate limiting | 15 | tool functions |
| Error handling | 15 | `while True` loops + sensitive calls |
| Tool scope & input validation | 15 | risky params of tool functions |
| Permissive defaults | 10 | governance-flag bindings |

## Shared machinery

**Sensitive calls** are detected by two tables in `agentgauge/astutils.py`:
exact dotted names (`os.system`, `subprocess.run`, `shutil.rmtree`, `eval`,
`requests.delete`, ...) and distinctive method suffixes flagged on any
receiver (`.rmtree()`, `.charge()`, `.transfer_funds()`, ...). Generic
suffixes (`run`, `delete`, `system`) are deliberately excluded.

**Tool functions** — the site population for rules 2, 3, and 5 — are
functions decorated with a `*tool*` decorator (`@mcp.tool()`, `@tool`) or
containing a sensitive call.

Global limitations, inherited by every rule:

- **Import aliasing:** resolved for `as`-imports. `import subprocess as sp;
  sp.run(cmd)` and `from shutil import rmtree as rt; rt(path)` both resolve
  to their canonical dotted name (`build_import_aliases` in astutils.py) and
  are caught exactly as if written unaliased. Still missed: re-assignment
  aliasing (`run = subprocess.run`), aliasing through a second layer of
  indirection, and function-local imports shadowed by control flow.
- **Dynamic calls:** `getattr(os, "remove")(p)`, `funcs["rm"](x)` are
  invisible to any static name-based scan.
- **Python only:** governance settings living in JSON/YAML/env config are
  not seen (see rule 6).
- **Vocabulary is extensible, not overridable:** every keyword list below
  can be *added to* per project via `[tool.agentgauge]` in pyproject.toml
  (see "Configuration" below) — never replaced. A team can teach a rule a
  new word; it can't make a rule stop recognizing the built-in ones.

## Rule 1 — Human oversight (`human-oversight`, 25 pts)

**Heuristic:** every sensitive call must have approval *vocabulary*
(`approv`, `confirm`, `consent`, `authoriz`, `human`, or builtin `input()`)
in an **enforcing position** within its enclosing scope (the containing
function including decorators; the whole module for top-level calls): the
identifier must be the callee of a call, appear in the test of an
`if`/`while`/`assert`, or name a decorator. A bare assignment or a keyword
argument passed to an unrelated call does not count — those are never
enforcing positions.

- **Catches:** sensitive calls in functions with zero approval machinery —
  the auto-executing agent tool. Also catches the dead-variable and
  wrong-keyword-argument shapes below, which earlier versions missed.
- **False passes:** position ≠ correctness. `if approved: rmtree(path)`
  passes even when `approved = True` is hardcoded two lines above with no
  real check behind it — confirming the *position* is enforcing, not that
  the tested value's truth ever came from an actual approval. That would
  require full data-flow analysis, out of scope for a static heuristic.
- **False failures:** approval enforced in a helper this function calls;
  teams using vocabulary we don't know ("vet", "greenlight").
- **Fixed (previously a false pass):** `approved = False` sitting unused
  next to the call, or `require_approval=False` passed as a keyword
  argument or parameter default, no longer satisfy this rule — neither is
  an enforcing position. See "Cross-rule interactions" below.
- **Configurable:** `extra_approval_markers` in `[tool.agentgauge]` adds to
  the built-in stems (e.g. a team using "vet"/"greenlight" instead of
  "approve"/"confirm" no longer has to fork the source).

## Rule 2 — Audit logging (`audit-logging`, 20 pts)

**Heuristic:** every tool function must contain a call whose dotted name
has a `log`/`logger`/`logging`/`audit` **token** (split on `.` and `_`) —
so `logger.info` and `audit_log` count, `login()` does not.

- **Catches:** tool functions with no logging call at all.
- **False passes:** any log call counts, however useless
  (`logger.info("hi")`); we can't verify actor/action/args are recorded.
  Any function with a log-like name counts, even `delete_logs()`.
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
  `rate_limiter = None` passes; a misconfigured limiter passes.
- **False failures:** limiting done at infrastructure level (API gateway,
  middleware, global semaphore elsewhere). Repos doing it right at the
  infra layer will systematically under-score, unless...
- **Configurable:** `assume_external_rate_limiting = true` zeroes out this
  category's sites entirely for gateway-fronted deployments — the category
  scores full marks the same way it does when no tool functions exist at
  all (see "Zero sites → full marks" above). `extra_rate_limit_markers`
  adds project-specific vocabulary the same way rule 1 and 2's extra
  markers do.

## Rule 4 — Error handling (`error-handling`, 15 pts)

**Heuristic:** two site types. (a) Every unconditional loop
(`while True:`, `while 1:`) must contain an exit that actually leaves it —
a `break` at *this* loop's level (a `break` in a nested loop exits only
the inner one), a `return`/`raise` not inside a nested `def`, or
`sys.exit`. (b) Every sensitive call must sit in the **body** of a `try` —
handlers, `else`, and `finally` don't count, because code there is not
protected by that try.

- **Catches:** exit-free polling loops (the runaway-agent shape) and naked
  sensitive calls — including breaks-in-nested-loops and
  calls-inside-except-handlers that naive checks bless.
- **False passes:** unreachable exits (`if False: break`); a `raise`
  caught by a try inside the same loop; `except: pass` counts as handled
  even though swallowing errors is its own smell.
- **Won't catch:** semantically infinite loops (`while not done:` where
  `done` never changes), infinite recursion, unbounded generators.
  Termination is undecidable; our line is "syntactically unconditional
  loops only".

## Rule 5 — Tool scope & input validation (`input-validation`, 15 pts)

**Heuristic:** parameters of tool functions whose names contain a risky
token (`path`, `file`, `dir`, `cmd`, `command`, `query`, `sql`, `url`,
`host`, `target`, ...) must be referenced by a validation construct in the
function: an `if`/`while`/`assert` test mentioning the parameter, or a
call with validation vocabulary (`validate*`, `sanitize`, `check*`,
`shlex.quote`, allowlist names) receiving it.

- **Catches:** the canonical MCP hole — `path`/`cmd`/`query` flowing
  straight into `open()`/`subprocess`/a DB.
- **False passes:** any `if` mentioning the param counts (`if path:` is a
  truthiness check, not validation); validation *after* use passes.
- **False failures / blind spots:** validators we don't recognize by name
  (`normalize(path)`). A risky value in a param named `p` is invisible.
- **Type-annotation evidence:** `Literal["a", "b"]` (a closed set of
  allowed values) and `Annotated[T, Field(...)]` (the FastMCP/Pydantic
  idiom for declaring pattern/length/range constraints) both count as
  validation — the presence of the construct is the proof, exactly like
  rule 6 trusts a boolean literal without tracing where it came from. This
  only checks that a `Field(...)` call appears in the annotation's
  metadata, not what constraints it declares — `Annotated[str, Field()]`
  with no arguments at all still counts, the same way any recognized
  validator call counts regardless of whether its logic is actually
  correct.
- **Configurable:** `extra_risky_params` and `extra_validation_tokens` add
  project-specific vocabulary on either side of the check.

## Rule 6 — Permissive defaults (`permissive-defaults`, 10 pts)

**Heuristic:** inverted category — sites exist only where a governance
knob appears. Every binding of a recognized flag name to a boolean
constant (assignments including attribute targets, keyword arguments,
parameter defaults; any casing, underscores ignored) is judged:
dangerous-when-True flags (`auto_approve`, `skip_confirmation`,
`allow_all`, `bypass_safety`, ...) must be `False`; dangerous-when-False
flags (`require_approval`, `human_in_the_loop`, `verify`, `safe_mode`,
`sandbox`, ...) must be `True`.

- **Catches:** permissive booleans wherever Python can spell them,
  including `requests.get(url, verify=False)`.
- **Not sites:** non-constant bindings (`require_approval = load_config()`)
  — we don't guess at values we can't see.
- **Blind spots:** **non-Python config** — JSON/YAML/`.env`, which is where
  real deployments (e.g. `claude_desktop_config.json`) actually set these.
- **Configurable:** `extra_dangerous_when_true` / `extra_dangerous_when_false`
  add project-specific flag names (`yolo_mode = True` no longer has to be a
  blind spot once it's named in config) — normalized the same
  case/underscore-insensitive way as the built-in lists.
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

## Configuration

An optional `[tool.agentgauge]` table in `pyproject.toml` (or a file passed
via `--config`) tunes a scan without forking source. Every key defaults to
today's built-in behavior — a project with no config file scans identically
to one with an empty table.

```toml
[tool.agentgauge]
min_score = 80                              # default for --min-score
exclude = ["tests/fixtures/*", "**/generated_*.py"]
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

`--min-score` on the command line overrides `min_score` in config; an
explicit `--config PATH` overrides discovery. Discovery looks for
`pyproject.toml` next to the scan target only (inside it for a directory,
alongside it for a single file) — no upward directory search, so a scan's
config source is always predictable, never "found somewhere above me."
A present-but-malformed config file is a usage error (exit `2`); a missing
one is not an error at all.

`disabled_rules` removes a category from the scan entirely — `max_score`
in the report drops below 100 rather than the remaining categories
silently renormalizing up to fill the gap. A `--min-score` threshold set
for a full 100-point scan means less once a category is disabled; that
tradeoff is the caller's to make, not something agentgauge should hide.

### Suppressing individual findings

`# agentgauge: ignore` on the same source line as a finding suppresses it;
`# agentgauge: ignore[human-oversight, error-handling]` suppresses only the
named rules on that line. A suppressed finding is removed from the report
and its site is credited as passed — matched against real COMMENT tokens
(via `tokenize`), so a string literal that happens to contain the marker
text is never mistaken for one.

**A suppression cannot buy back `FAIL_CRITICAL`.** Suppressing a finding on
a critical sink (payment, file delete, shell exec, code exec, remote
delete) still forces the verdict, and the scan report says so explicitly
(`critical_suppressed` in JSON/SARIF output; a CLI warning line). This is
deliberate: the entire reason `ScanReport.verdict` exists is that
score-averaging must never be able to hide one catastrophic miss behind a
hundred compliant sites (issue #1) — a one-line comment achieving the same
outcome would just be issue #1 wearing a suppression instead of an
average. Suppression is for decluttering noise on non-critical categories
during incremental adoption, not for silencing the one guarantee this tool
makes.

### Output formats

`--json` emits agentgauge's own report shape. `--sarif` emits SARIF 2.1.0
for ingestion by GitHub/GitLab code scanning and most AppSec dashboards —
`critical` findings map to SARIF `error` level, everything else to
`warning`, mirroring the same split the verdict itself uses. The two flags
are mutually exclusive.
