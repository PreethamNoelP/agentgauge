<div align="center">

# 🛡️ agentgauge

**Find the dangerous things your AI agent can do without asking a human.**

A static scanner for MCP servers and AI-agent tool code. It finds every function a model can call, follows what those functions do across your repository, and flags destructive actions — deleting files, running commands, executing SQL, moving money — that have no human approval, logging, limits or input validation in front of them.

[![CI](https://github.com/PreethamNoelP/agentgauge/actions/workflows/ci.yml/badge.svg)](https://github.com/PreethamNoelP/agentgauge/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agentgauge)](https://pypi.org/project/agentgauge/)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/PreethamNoelP/agentgauge/blob/main/LICENSE)

</div>

---

## Quick start

```console
$ pip install agentgauge
$ cd your-project
$ agentgauge .
```

Python 3.11+. No dependencies, no account, no network access, and it never
runs the code it reads. (Before the first PyPI release:
`pip install git+https://github.com/PreethamNoelP/agentgauge.git@v0.3.0`.)

## What it catches

A notes server written the way MCP tutorials teach:

```python
NOTES = Path.home() / "notes"

@mcp.tool()
def read_note(name: str) -> str:
    return (NOTES / name).read_text()

@mcp.tool()
def delete_note(name: str) -> str:
    os.remove(NOTES / name)
    return "deleted"
```

```console
$ agentgauge .

  Human oversight                      0.0 / 25  (0/3 sites passed)
  Tool scope & input validation        0.0 / 15  (0/2 sites passed)
  ...
  GOVERNANCE SCORE                    10.0 / 100
  VERDICT                           FAIL_CRITICAL

  src/notes_mcp/server.py:18  [input-validation]
    parameter 'name' of tool 'read_note' reaches a file path or sensitive call without validation
    fix: Validate before use: an allowlist or containment check (`if not Path(path).resolve().is_relative_to(ROOT): raise`), ...

  src/notes_mcp/server.py:26  [human-oversight]
    file delete call 'os.remove' in 'delete_note' has no human-approval check before it
    fix: Gate the call behind an explicit approval that runs first, e.g. `if not await request_approval(...): return` before it executes
```

Any model connected to that server — or any prompt injection reaching it —
can read `../../.ssh/id_rsa` and delete files without anyone being asked.
agentgauge says so, at the exact line, with the fix.

## Who it is for

- **Developers building MCP servers or agent tools** — catch the risky
  patterns before you publish or deploy.
- **Teams adopting AI agents** — one rule for every repository: nothing an
  agent can trigger deletes, executes or pays without a human check, a log
  and sensible limits. Enforced in CI on every pull request.
- **Security and platform teams** — a zero-dependency, offline, read-only
  tool you can approve quickly, with SARIF output for GitHub code scanning
  and a written trail of every accepted risk.
- **Anyone evaluating a third-party MCP server** before installing it:
  `agentgauge --no-config path/to/server`.

## What it checks

Six questions, for every action a model can reach:

| Category | Weight | The question |
|---|---|---|
| Human oversight | 25 | Is every destructive action preceded by a human approval? |
| Audit logging | 20 | Does every tool, or something it calls, record what it did? |
| Rate limiting | 15 | Is every tool behind a limiter (or a declared gateway)? |
| Error handling | 15 | Are failures handled — not swallowed — and can agent loops end? |
| Input validation | 15 | Are paths, commands, queries and URLs validated before use? |
| Permissive defaults | 10 | Is `auto_approve=True` or `verify=False` set in code or an MCP client config? |

Destructive actions it recognizes: file deletion, shell and process
execution, `eval`/`exec`/unsafe deserialization, dynamic SQL, payments
(Stripe-style SDKs and payment-API HTTP calls), and remote deletes (cloud
storage, databases, Kubernetes).

Frameworks it understands: MCP (FastMCP and the low-level SDK), LangChain,
OpenAI Agents SDK, LlamaIndex, Pydantic AI, AutoGen, Semantic Kernel, and
class-based tools. Others can be taught with one line of config.

## The verdict

| Verdict | Meaning | Exit code |
|---|---|---|
| `FAIL_CRITICAL` | a destructive action a model can reach has no human approval before it | 1 |
| `FAIL_SCORE` | nothing critical, but the score is below the threshold (default 70) | 1 |
| `INCOMPLETE` | the scan could not judge everything: an unparseable file, no recognizable tools, or nothing to check | 0, or 1 with `--fail-on-incomplete` |
| `PASS` | none of the above | 0 |

The 0–100 score is a trend line. The verdict is what belongs in CI: one
ungated payment cannot hide behind ninety-nine safe tools, and neither an
inline `# agentgauge: ignore` nor a baseline can clear a critical finding.
Only a reviewed `accepted_risks` entry can — with a written reason that
every report repeats.

## How it decides

- **Only code an agent can reach is judged.** A `subprocess.run` in your
  build script is not an agent risk; one reached from an `@mcp.tool()` is,
  even three helper calls and two files away. On `pip`, `requests` and
  `black`, agentgauge reports zero critical findings.
- **Approval must come first, and from a human.** It has to run before the
  action, on the way to it. A check placed after the action does not count,
  nor does a tool argument named `confirm` (the model sets it), nor
  `approved = True`, nor `if settings.auto_approve:`, nor a permission
  check like `is_authorized()`. MCP elicitation (`await ctx.elicit(...)`)
  does.
- **Inputs are found by where they go, not only by their name.** A
  parameter called `name` that ends up in a file path is checked exactly
  like one called `path`.

The full rules, with every known blind spot:
[RULES.md](https://github.com/PreethamNoelP/agentgauge/blob/main/RULES.md).

## How accurate it is

A labelled benchmark runs in CI and fails the build if results drift from
the labels in either direction:

| Rule | Precision | Recall |
|---|---:|---:|
| human-oversight | 79.2% | 86.4% |
| input-validation | 78.6% | 100.0% |
| error-handling | 92.9% | 100.0% |
| permissive-defaults | 100.0% | 100.0% |
| **all measured rules** | **83.3%** | **93.8%** |

Critical verdict correct for 14 of 14 test projects. *Precision*: how often
a finding is a real problem. *Recall*: how many real problems it finds. The
benchmark projects are written in the shape of real servers rather than
taken from real repositories, and they deliberately include the cases
agentgauge gets wrong —
[benchmarks/README.md](https://github.com/PreethamNoelP/agentgauge/blob/main/benchmarks/README.md).

## Use it in CI

**GitHub Actions**

```yaml
- uses: PreethamNoelP/agentgauge@v0.3.0
  with:
    path: .
    fail-on-incomplete: "true"
```

With GitHub code scanning (findings appear on the pull request):

```yaml
- uses: PreethamNoelP/agentgauge@v0.3.0
  with:
    sarif-file: agentgauge.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: agentgauge.sarif
```

Inputs: `path`, `min-score`, `scope`, `fail-on-incomplete`, `sarif-file`,
`config`, `no-config`. For the strictest supply-chain posture, pin the tag's
full commit SHA instead of `v0.3.0`.

**pre-commit**

```yaml
repos:
  - repo: https://github.com/PreethamNoelP/agentgauge
    rev: v0.3.0
    hooks:
      - id: agentgauge
        args: [--fail-on-incomplete]
```

## Command line

```console
$ agentgauge .                              # scan from the repository root
$ agentgauge src/server.py                  # a single file
$ agentgauge . --json                       # machine-readable report
$ agentgauge . --sarif > agentgauge.sarif   # SARIF 2.1.0 for code scanning
$ agentgauge . --min-score 80               # stricter threshold (0 disables)
$ agentgauge . --fail-on-incomplete         # treat reduced coverage as failure
$ agentgauge . --no-config                  # ignore the repo's own settings
$ agentgauge . --scope all                  # judge every function with a sink
$ agentgauge . --baseline base.json --update-baseline   # record today's findings
$ agentgauge . --baseline base.json         # then fail only on new ones
```

Run it from the repository root, so reported paths match what code scanning
expects.

## Configuration

Optional, in `pyproject.toml`:

```toml
[tool.agentgauge]
min_score = 70
exclude = ["tests/*", "scripts/"]
extra_tool_decorators = ["expose"]         # your framework's tool decorator
extra_approval_markers = ["greenlight"]    # your approval helper's name
assume_external_rate_limiting = true       # a gateway limits calls

[[tool.agentgauge.accepted_risks]]
rule = "human-oversight"
file = "src/server.py"
function = "rebuild_index"
reason = "Runs a fixed make target; no model input reaches it (SEC-142)"
```

Settings are validated strictly: a typo, an unknown rule, or a setting that
would quietly switch a check off is an error, not a silent no-op. When you
scan code you do not control, use `--no-config` — otherwise a repository's
own settings could exclude its files or accept its own risks. Full
reference:
[RULES.md#configuration](https://github.com/PreethamNoelP/agentgauge/blob/main/RULES.md#configuration).

## Is it safe to run?

Yes, including on code you don't trust:

| | |
|---|---|
| **Network** | None. It imports only the Python standard library: `argparse, ast, collections, dataclasses, fnmatch, functools, hashlib, io, json, os, pathlib, re, sys, tokenize, tomllib, typing`. No HTTP client, telemetry or update check. |
| **Code execution** | None. Scanned code is parsed, never imported or run. |
| **Files written** | Only the baseline file you ask for with `--update-baseline`. |
| **Files read** | Python files and MCP config files under the target. Links leading outside the target are refused. |
| **Environment** | Never read — no environment variables, no credentials. |
| **Dependencies** | None at runtime, so no supply chain to audit. |

Every row is enforced by an automated test. Reports contain file paths and
identifier names from your code — never string literals, secrets or source
lines. See
[SECURITY.md](https://github.com/PreethamNoelP/agentgauge/blob/main/SECURITY.md)
to report a vulnerability.

## What it cannot do

agentgauge reads code; it does not run it or trace every value. So:

- It can be **wrong in both directions** — the benchmark above shows how
  often. Treat findings as a reviewer's notes, not a verdict from a judge.
- It does not notice an approval check that is **written backwards**
  (acting when approval is refused), or a dangerous call reached through a
  **lookup table** or a computed name.
- It cannot tell that a **custom decorator** such as `@guarded` asks a
  human — teach it with `extra_approval_markers`, or record an accepted
  risk.
- Logging and rate limiting are checked for **presence**, not correctness.
- **Python only.** TypeScript and JavaScript MCP servers are not supported
  yet.
- A 100/100 is **not a certification**. It means the patterns agentgauge
  knows are in place.

## How it works

1. **Find the tools.** Decorators (`@mcp.tool()`, `@tool`,
   `@function_tool`, ...), registrations (`Agent(tools=[...])`,
   `FunctionTool.from_defaults(fn=...)`), and class-based tools.
2. **Follow the calls** from those tools across files — imports, methods,
   helpers, callbacks — to everything an agent can reach.
3. **Check each destructive action** for approval that runs first, error
   handling, and validated inputs; check each tool for logging and rate
   limiting; check settings for permissive defaults.
4. **Report** findings with the exact line and a fix, a score, and a
   verdict — as text, JSON or SARIF.

Two passes over the repository, one syntax-tree walk per file per pass, no
code execution. Design details are in
[CONTRIBUTING.md](https://github.com/PreethamNoelP/agentgauge/blob/main/CONTRIBUTING.md).

## Project status

Version 0.3 — usable today, and the rules are still being refined. Tested
on Linux and Windows, Python 3.11–3.13: 1,187 automated tests, strict type
checking, linting, the accuracy benchmark, and a build-and-install check of
the published package, on every change.

**Roadmap:** a benchmark built from real open-source MCP servers ·
backwards-approval detection and deeper value tracking ·
TypeScript/JavaScript support · plugins for custom rules · new checks for
leaked secrets, server-side request forgery and over-broad tool
permissions.

## Contributing

The most useful contribution is a report of a wrong result — a real problem
it missed, or a false alarm — with a small code sample. Each one becomes a
test case. See
[CONTRIBUTING.md](https://github.com/PreethamNoelP/agentgauge/blob/main/CONTRIBUTING.md)
and the
[changelog](https://github.com/PreethamNoelP/agentgauge/blob/main/CHANGELOG.md).

## License

[Apache License 2.0](https://github.com/PreethamNoelP/agentgauge/blob/main/LICENSE).
Created by **Preetham Noel P** —
[GitHub](https://github.com/PreethamNoelP) ·
[LinkedIn](https://www.linkedin.com/in/preethamnoelp)
