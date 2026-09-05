# agentgauge playground

A static, client-side page that runs the real `agentgauge` scanner in the
browser via [Pyodide](https://pyodide.org/) (Python compiled to
WebAssembly). Paste a Python file, or load one of three examples, and get
the same score/verdict/findings the CLI would report -- computed entirely
on your machine. No server, no upload.

Not yet published (see repository README/plan for status) -- to preview
locally:

```console
$ cd docs
$ python -m http.server 8000
```

then open `http://localhost:8000/`.

## How it works

`agentgauge.astutils.FileContext.from_source()` and
`agentgauge.scoring.score_contexts()` are pure in-memory APIs -- no
filesystem access anywhere in `astutils.py`, `scoring.py`, `models.py`, or
`sarif.py`. Filesystem coupling (file walking, symlink checks, TOML
discovery) lives only in `scanner.py` and `config.py`'s `load_config`,
neither of which this page needs: it hands `FileContext.from_source()` the
pasted text directly and renders `ScanReport.to_dict()`.

`assets/app.js` boots Pyodide, fetches the vendored modules below into
Pyodide's in-memory filesystem, imports them, and calls straight into that
API for every scan.

## `vendor/agentgauge/`

A plain copy of the ~13 stdlib-only modules the playground needs:
`__init__.py`, `astutils.py`, `config.py`, `models.py`, `scoring.py`,
`sarif.py`, and everything under `rules/`. Deliberately **not**
`cli.py` / `scanner.py` / `__main__.py`, which are filesystem-coupled and
unused here.

These are synced copies, not symlinks (GitHub Pages serves plain files;
keeping this a static site with no build step means no wheel-building CI
job either). `tests/test_playground_assets.py` asserts every file here is
byte-identical to its counterpart under `agentgauge/`, so a change to the
real package that isn't mirrored here fails the test suite instead of
silently making the demo lie about what it's running.

To refresh after changing the real package:

```console
$ cp agentgauge/__init__.py agentgauge/astutils.py agentgauge/config.py \
     agentgauge/models.py agentgauge/scoring.py agentgauge/sarif.py \
     docs/vendor/agentgauge/
$ cp agentgauge/rules/*.py docs/vendor/agentgauge/rules/
$ python -m pytest tests/test_playground_assets.py -q
```

## `vendor/samples/`

Three example files the playground can load:

- `vulnerable_server.py` / `clean_server.py` -- verbatim copies of
  `tests/fixtures/`'s calibrated 0/100 and 100/100 canaries (the project's
  own top-level README already uses the vulnerable one as its front-door
  demo, so reusing it here is consistent, not a new exposure).
- `mixed_server.py` -- a new, playground-only fixture: a plausible MCP
  server with a few properly-governed tools and a couple of realistic
  gaps, scoring in the 70s/100 with a `PASS` verdict. The two canaries
  are deliberately extreme (regression anchors, not representative code);
  this one exists so the live demo also shows the nuanced,
  actionable-findings story a real scan usually produces. It is demo
  content only -- not a CI-pinned canary like the other two.
