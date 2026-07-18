# agentgauge

A static governance scanner for MCP servers and AI agent tool-calling code
— think *a linter for the OWASP Agentic Top 10*. Point it at a Python
repo; it parses the source with Python's `ast` module (no regex, no
execution), checks six governance categories, and returns a 0–100 score
plus specific findings with fixes.

Zero dependencies. Python 3.11+. `pytest` needed only to run the tests.

## Quickstart

```console
$ python -m agentgauge path/to/repo
$ python -m agentgauge path/to/server.py          # single file works too
$ python -m agentgauge path/to/repo --json        # machine-readable report
$ python -m agentgauge path/to/repo --min-score 70   # CI gate
```

Example output:

```
agentgauge: ./demo
scanned 1 Python file(s)

  Human oversight                     12.5 / 25  (1/2 sites passed)
  Audit logging                       10.0 / 20  (1/2 sites passed)
  Rate limiting                        7.5 / 15  (1/2 sites passed)
  Error handling                       5.0 / 15  (1/3 sites passed)
  Tool scope & input validation        7.5 / 15  (1/2 sites passed)
  Permissive defaults                  0.0 / 10  (0/1 sites passed)
  ----------------------------------------------------------
  GOVERNANCE SCORE                    42.5 / 100

Findings (7):

  agent_tools.py:28  [human-oversight]
    shell exec call 'subprocess.run' in 'run_shell' has no human-approval check in scope
    fix: Gate the call behind an explicit approval, e.g. `if not request_approval(...): return` before it executes
  ...
```

Exit codes (the CI contract):

| Code | Meaning |
|---|---|
| `0` | scan completed (and met `--min-score`, if given) |
| `1` | score below `--min-score` |
| `2` | bad invocation: target missing, or **zero Python files scanned** — a score over zero evidence is never reported as a pass |

## The six categories

| Category | Weight | Question it asks |
|---|---|---|
| Human oversight | 25 | Does every sensitive action (file delete, shell exec, payment, ...) have an approval/confirmation check nearby? |
| Audit logging | 20 | Does every tool function make a log/audit call? |
| Rate limiting | 15 | Does every tool function reference a rate limit or throttle? |
| Error handling | 15 | No exit-free `while True` loops; sensitive calls wrapped in `try/except`? |
| Tool scope & input validation | 15 | Are risky parameters (`path`, `cmd`, `query`, `url`, ...) validated before use? |
| Permissive defaults | 10 | Are flags like `auto_approve=True` or `require_approval=False` set to the dangerous side? |

A category with zero applicable sites scores full marks — you can't fail a
check that never applied.

## How it works — and how much to trust it

Every check is a **heuristic** over the AST: vocabulary matching for
oversight/logging/rate-limiting, structural analysis for error handling
(including telling a `try` body apart from its `except` handlers, and a
`break` in a nested loop apart from one that actually exits), and
name-based taint-ish checks for input validation. Heuristics have known
false passes and false failures — for example, presence of approval
vocabulary is checked, not that it actually gates execution.

**[RULES.md](RULES.md) documents every heuristic with its exact
limitations and planned fixes.** Read it before trusting a score in
anger; a governance tool that hides its own blind spots would fail its
own audit.

## Repository layout

```
agentgauge/
├── models.py        # Finding + CategoryResult (scoring semantics live here)
├── astutils.py      # parent map, dotted-name resolution, sensitive-call
│                    #   tables, tool-function detection
├── rules/           # the six rules; each exposes RULE_ID, CATEGORY,
│                    #   WEIGHT, check(ctx) -> (sites, passed, findings)
├── scoring.py       # ALL_RULES registry, cross-file aggregation, ScanReport
├── scanner.py       # file walking, encoding-safe parsing, skip lists
└── cli.py           # argparse CLI, human/JSON output, exit codes
tests/
├── fixtures/        # one deliberately vulnerable server (scores 0.0),
│                    #   one deliberately clean one (scores 100.0)
└── test_*.py        # unit tests per module/rule + end-to-end integration
```

## Running the tests

```console
$ python -m pytest tests/
```

Note: scanning agentgauge's own repository will flag
`tests/fixtures/vulnerable_server.py` — it is *supposed* to be terrifying.

## Roadmap

- Enforcing-position check for approval vocabulary (kills the
  dead-variable false pass without data-flow analysis)
- Configurable keyword lists (approval / logging / rate-limit / flag names)
- Read type annotations (`Literal`, Pydantic `Field`) as validation evidence
- Scan known config files (`claude_desktop_config.json`, `mcp.json`, ...)
  for permissive defaults living outside Python
- Resolve import aliases so `import subprocess as sp; sp.run(...)` is seen
- `assume_external_rate_limiting` option for gateway-fronted deployments
