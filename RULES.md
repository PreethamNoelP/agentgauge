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

- **Import aliasing:** `import subprocess as sp; sp.run(cmd)` is missed
  (`sp.Popen` is still caught — `Popen` is a suffix entry). Fix: resolve
  import statements. Planned.
- **Dynamic calls:** `getattr(os, "remove")(p)`, `funcs["rm"](x)` are
  invisible to any static name-based scan.
- **Python only:** governance settings living in JSON/YAML/env config are
  not seen (see rule 6).

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
- **Planned:** configurable keyword list, so teams can add their own
  approval vocabulary without editing source.

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
  infra layer will systematically under-score.
- **Planned:** an `assume_external_rate_limiting` config option to zero
  out this category's sites for gateway-fronted deployments.

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
  (`normalize(path)`); **type-annotation validation** — Pydantic `Field`
  constraints and `Literal` types, common in FastMCP, are not read at all.
  A risky value in a param named `p` is invisible.
- **Planned:** read annotations (`Literal`, `Annotated[..., Field(...)]`)
  as validation evidence — the highest-value v2 improvement here.

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
- **Blind spots:** flag names outside our lists (`yolo_mode = True`);
  **non-Python config** — JSON/YAML/`.env`, which is where real
  deployments (e.g. `claude_desktop_config.json`) actually set these.
- **Planned:** a config-file scanner scoped to known filenames — pure-data
  formats are *more* statically tractable than Python, so error rates will
  be lower than the AST rules. User-supplied flag-name lists ride along
  with the general keyword-config mechanism.

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
