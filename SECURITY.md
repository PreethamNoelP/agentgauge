# Security policy

## Reporting a vulnerability

Please report security issues privately via
[GitHub Security Advisories](https://github.com/PreethamNoelP/agentgauge/security/advisories/new)
rather than a public issue. You should get an acknowledgement within a week.

## What counts as a vulnerability in agentgauge

agentgauge is run on untrusted input: its whole job is to scan
repositories, including hostile ones, and it is often run in CI with
repository tokens in the environment. The following are security issues,
not ordinary bugs:

1. **Code execution.** agentgauge must never execute, import, or evaluate
   the code it scans. Any path that does — through a config file, a source
   file, or anything else — is a vulnerability.
2. **Escaping the scan target.** Reading or writing files outside the paths
   the caller named.
3. **Denial of service on a bounded input.** A single crafted `.py` file
   that hangs the scan or exhausts memory. Files are read one at a time,
   capped at `scanner.MAX_FILE_BYTES`, and parse failures are recorded and
   skipped — unbounded growth on a file inside that cap is in scope.
4. **Output injection.** Findings are rendered from attacker-controlled
   file names and source text. Control characters are escaped before they
   reach a terminal (`cli._safe`); JSON and SARIF are serialized by
   `json.dumps`. A path from scanned input to raw terminal control
   sequences, or to JSON/SARIF a consumer misparses, is in scope.
5. **Silently weakening the gate.** A way to make an ungated critical sink
   report `PASS` — through config, a suppression comment, or a parse
   failure that is not reported — is treated as a security issue. That
   verdict is the one guarantee this tool makes; see
   `ScanReport.verdict`.

## What does not count

- **A missed finding (false negative).** agentgauge is a documented set of
  heuristics, not a sound analysis. Please still report it, as a normal
  issue — closing detection gaps is the main way this tool improves.
  `RULES.md` lists the known blind spots.
- **A false positive.** Same: a normal issue, and a valuable one.
- **A weak governance pattern in code agentgauge scores highly.** The
  score is a signal, not an audit result.

## What agentgauge does with your code

Stated precisely, because the whole point of this tool is that you point it
at code you cannot afford to leak:

- **Nothing is transmitted.** The package's complete import list is
  `argparse, ast, dataclasses, fnmatch, functools, io, json, os, pathlib,
  re, sys, tokenize, tomllib, typing`. No HTTP client, no socket, no DNS,
  no telemetry, no update check.
- **Nothing is written.** The only file-opening calls in the package are
  `tokenize.open` (read), `path.open("rb")` for the config file (read), and
  `os.devnull` when stdout's pipe closes. No temp files, no cache, no
  persistence of any kind — a scan leaves the filesystem exactly as it was.
- **Nothing is executed.** `ast.parse` and `tokenize` only. Scanned code is
  never imported, `eval`'d, `exec`'d, or run as a subprocess.
- **Nothing outside the target is read.** `.py` files under the path you
  name, plus one config file. Symlinks resolving outside the scan root are
  refused rather than followed.
- **The environment is never read.** No `os.environ`, no `getenv`, no
  credential helpers.

### The counterpart: what the report contains

agentgauge sends nothing anywhere, but the report it prints is derived from
your source. It carries file paths, function and parameter names, resolved
call names, and the names and boolean values of governance flags. It does
**not** carry string literals, secret values, or source lines.

So the sensitivity of an agentgauge report is roughly the sensitivity of
your identifier names and file layout. That matters when a report leaves
your machine by a route agentgauge is not involved in — uploading SARIF to
a third-party dashboard, pasting JSON into a public issue, or a CI log.
Reports also name the config file in use; that path is relative to the
working directory whenever possible, so logs do not disclose a machine's
directory layout.

## Supply chain

agentgauge has no runtime dependencies. `pytest` is required only to run
the test suite. That is deliberate and intended to stay that way: a
governance scanner that pulls in a transitive dependency tree is a poor
trade for a security-sensitive CI step.
