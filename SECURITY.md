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

## Supply chain

agentgauge has no runtime dependencies. `pytest` is required only to run
the test suite. That is deliberate and intended to stay that way: a
governance scanner that pulls in a transitive dependency tree is a poor
trade for a security-sensitive CI step.
