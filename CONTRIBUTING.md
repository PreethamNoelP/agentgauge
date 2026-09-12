# Contributing to agentgauge

Contributions are welcome — especially new rules, vocabulary additions, and
reports of false positives or false negatives.

## Setup

```console
$ git clone https://github.com/PreethamNoelP/agentgauge.git
$ cd agentgauge
$ pip install -e ".[dev]"
$ python -m pytest tests/ -q
$ mypy                            # --strict, configured in pyproject.toml
$ ruff check agentgauge/ tests/
```

Python 3.11+ and no other runtime dependency. `mypy` and `ruff` are
dev-only and both gate CI: the package ships a `py.typed` marker, which
promises anyone writing a third-party rule that the annotations are real,
and an unenforced promise is how it silently stops being true.

`tests/fixtures/` is excluded from ruff. Those files are scanner *input* —
they reference undefined names on purpose because they are only ever
`ast.parse`d, never imported — so their F821s are the point of the files.

## The bar for a change

**Every behavior change needs a test that fails without it.** Not a test
that merely exercises the new code — a test that pins the specific wrong
answer the old code gave. Most of this project's real bugs looked like
"scored 100/100 on code that shells out"; the suite's job is to make each
of those irreproducible.

**Zero runtime dependencies.** A governance scanner that drags in a
dependency tree is a worse deal for a CI step than one that is slightly
less clever. If you need a library, make the case in an issue first.

**Never execute scanned code.** No `import`, `eval`, `exec`, or subprocess
of anything under the scan target. `ast.parse` and `tokenize` only.

**Document the blind spot.** Every heuristic in `RULES.md` states what it
does *not* catch. A rule without that is not finished — overstating what a
static scan can prove is the fastest way to make this tool useless.

## Adding a rule

A rule is one module in `agentgauge/rules/` exposing four names:

```python
RULE_ID = "my-rule"      # lowercase kebab-case; suppressions name it
CATEGORY = "My category"
WEIGHT = 10              # points out of 100

def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    """Return (sites, passed, findings)."""
```

Then:

1. Register it in `ALL_RULES` in `agentgauge/scoring.py`.
2. Add its id to `RULE_IDS` in `agentgauge/rules/__init__.py`
   (`test_rules_package.py` fails if you forget).
3. Rebalance `WEIGHT`s so they still total 100 — also checked by
   `test_rules_package.py`. Changing weights changes every user's score,
   so say so in `CHANGELOG.md`.
4. Ask the context for what you need (`ctx.functions`,
   `ctx.sensitive_calls`, `ctx.tool_functions`, `ctx.parents`) instead of
   walking the tree yourself where a cached view exists — six rules each
   doing their own walks is where scan time goes.
5. Add tests: `tests/test_rule_<name>.py`, plus a case in
   `tests/fixtures/vulnerable_server.py` (must fire) and, if the rule can
   pass, `tests/fixtures/clean_server.py` (must not fire).

Invariants your rule must keep, because scoring relies on them:

- `sites == passed + len(findings)`. Every applicable place is either
  compliant or has exactly one finding.
- Zero sites means the rule did not apply, which scores full marks. Never
  report a site you cannot judge. Note the scan-level consequence: if
  *every* rule reports zero sites the scan has proved nothing, so its
  verdict is `INCOMPLETE` rather than a vacuous 100/100 `PASS`. A rule that
  invents sites to avoid looking inapplicable breaks that guarantee.
- `critical=True` only for consequences that must fail a build on their
  own. A new source of critical findings means updating
  `CRITICAL_GATE_RULES` in `scoring.py`, or the verdict will not know the
  gate depends on your rule.

## Vocabulary

Sink tables live in `agentgauge/astutils.py`. `SENSITIVE_EXACT` requires a
full dotted name; `SENSITIVE_SUFFIX` matches a method name on *any*
receiver, so an entry there must be distinctive enough that a false
positive is implausible (`rmtree`, `delete_bucket`, `transfer_funds` — not
`run`, `delete`, `send`). A false positive on a critical sink fails
someone's build for no reason, which costs more trust than a missed
finding does.

## Pull requests

- Branch from `main`, one logical change per commit.
- `python -m pytest tests/ -q` green, and CI green on every matrix entry —
  including Windows, where path handling and glob case sensitivity have
  broken before.
- Update `CHANGELOG.md` under `Unreleased`.
- Update `RULES.md` if you changed what a rule catches or misses.
