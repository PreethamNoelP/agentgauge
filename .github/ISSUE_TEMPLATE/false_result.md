---
name: False positive or false negative
about: agentgauge flagged safe code, or missed unsafe code
labels: detection
---

## Which way round

- [ ] **False positive** — agentgauge flagged code that is properly governed
- [ ] **False negative** — agentgauge passed code that is not

## Minimal snippet

The smallest file that reproduces it. Please make it something you would be
happy to see added to the test suite verbatim.

```python

```

## What agentgauge said

```console
$ agentgauge snippet.py --json
```

## What it should have said, and why

For a false positive: which control is present, and where a static scan
could see it. For a false negative: which sink or gap was missed.

## Environment

- `agentgauge --version`:
- Python version:
- OS:
- Relevant `[tool.agentgauge]` config, if any:

---

Before filing, please check the "False passes" / "False failures" section
for the rule in [RULES.md](../../RULES.md) — some limits are known and
documented, and an issue confirming one is still useful, but say so.
