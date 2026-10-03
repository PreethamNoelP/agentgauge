# Accuracy benchmark

`benchmarks/run.py` scans a labelled corpus and reports per-rule precision
and recall. CI runs it on every change and fails when agentgauge's output
differs from the labels in either direction.

```console
$ python benchmarks/run.py              # table, exit 1 on drift
$ python benchmarks/run.py --markdown   # the table below
$ python benchmarks/run.py --corpus path/to/your/labelled/corpus
```

## Current results

| Rule | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| human-oversight | 19 | 5 | 3 | 79.2% | 86.4% |
| input-validation | 11 | 3 | 0 | 78.6% | 100.0% |
| error-handling | 13 | 1 | 0 | 92.9% | 100.0% |
| permissive-defaults | 2 | 0 | 0 | 100.0% | 100.0% |
| all measured rules | 45 | 9 | 3 | 83.3% | 93.8% |

Critical-verdict accuracy: 14/14 scan units (100.0%).

## What the corpus is — and is not

The corpus is **written for this benchmark**, in the shape of real MCP
servers and agent toolkits: the reference filesystem, SQLite and git
servers, a Stripe payments server, a tutorial-style notes server, a
low-level SDK `call_tool` dispatcher,
LangChain, OpenAI Agents SDK and LlamaIndex tools, a cross-file package,
ordinary library code with no tools, adversarial bypass attempts, and a
`known_limits.py` file of cases agentgauge gets wrong today.

It is **not** a sample of real-world repositories, so these numbers say how
the rules behave on the patterns the corpus covers, not how often those
patterns occur in the wild. Two consequences:

- The corpus is small (14 scan units, 57 labelled sites). One more case can
  move a percentage by several points.
- It was written by the same people who wrote the rules. The defence is in
  how labels are assigned (below), and in `known_limits.py`, which exists to
  keep known failures in the numbers instead of out of them.

The natural next step is a corpus of real open-source MCP servers, labelled
the same way; `--corpus` runs the same evaluation against any directory.

## How labels work

Ground truth is a trailing comment on the line a finding is reported on,
stating what a reviewer would conclude — not what agentgauge does:

```python
shutil.rmtree(target)  # expect: human-oversight, error-handling
os.remove(p)           # known-miss: human-oversight
conn.execute(q)        # known-fp: human-oversight
```

| Label | Meaning | Counts as |
|---|---|---|
| `expect` | a real issue agentgauge reports | true positive |
| `known-miss` | a real issue agentgauge does not report | false negative |
| `known-fp` | something agentgauge reports that is not a real issue | false positive |
| *(none)* | no issue, nothing reported | true negative |

Each scan unit (a file, or a directory for cross-file cases) also states
the verdict a reviewer would give it: `# expect-verdict: FAIL_CRITICAL` or
`NOT_CRITICAL`.

The run fails whenever agentgauge reports something other than
`expect` + `known-fp`. A fix that removes a false positive therefore has to
delete its `known-fp` label in the same commit, and a regression cannot slip
in as a quiet change in a percentage.

Four rules are measured. Audit logging and rate limiting are presence checks
("is there a logging call?"), so a reviewer's label would only restate the
rule's own definition; they are covered by the unit tests instead.

## Where agentgauge is wrong today

From `known_limits.py` and the `known-fp` labels elsewhere:

| Case | Effect |
|---|---|
| `if approved(): return` before the sink (wrong polarity) | missed: the sink runs exactly when approval was refused |
| a sink looked up in a dict (`ACTIONS[name](p)`) | missed |
| `getattr(os, name)` with a non-constant name | missed |
| approval enforced by a decorator whose name says nothing (`@guarded_by_policy_service`) | false positive |
| a validator with an unrecognized name (`normalize_under_root`) | false positive |
| a fixed, read-only subprocess call (`git status`, `git log`) | false positive |
| a validated read-only SQL query, or an allowlisted `PRAGMA` | false positive |
| a search-index `query` parameter | false positive |
| a value passed as one argv element (`git commit -m message`) | false positive |
