"use strict";

// Every stdlib-only agentgauge module needed to score a single in-memory
// file. Deliberately excludes cli.py / scanner.py / __main__.py, which are
// filesystem-coupled and unused here -- see docs/README.md.
const VENDOR_FILES = [
  "agentgauge/__init__.py",
  "agentgauge/astutils.py",
  "agentgauge/config.py",
  "agentgauge/models.py",
  "agentgauge/scoring.py",
  "agentgauge/sarif.py",
  "agentgauge/rules/__init__.py",
  "agentgauge/rules/oversight.py",
  "agentgauge/rules/audit.py",
  "agentgauge/rules/ratelimit.py",
  "agentgauge/rules/errorhandling.py",
  "agentgauge/rules/validation.py",
  "agentgauge/rules/defaults.py",
];

const SAMPLES = {
  vulnerable: "vendor/samples/vulnerable_server.py",
  clean: "vendor/samples/clean_server.py",
  mixed: "vendor/samples/mixed_server.py",
};

// A generous cap well under scanner.py's real 5 MB per-file limit -- this
// page has no file-size concept at all (it's a textarea), so this just
// keeps a pathological paste from freezing the tab.
const MAX_SOURCE_CHARS = 300_000;

const els = {
  status: document.getElementById("status"),
  statusText: document.getElementById("status-text"),
  source: document.getElementById("source"),
  scanBtn: document.getElementById("scan-btn"),
  editorHint: document.getElementById("editor-hint"),
  emptyState: document.getElementById("empty-state"),
  errorState: document.getElementById("error-state"),
  errorMessage: document.getElementById("error-message"),
  report: document.getElementById("report"),
  verdictBadge: document.getElementById("verdict-badge"),
  scoreValue: document.getElementById("score-value"),
  maxScoreValue: document.getElementById("max-score-value"),
  categories: document.getElementById("categories"),
  warnings: document.getElementById("warnings"),
  findingsCount: document.getElementById("findings-count"),
  findings: document.getElementById("findings"),
};

function setStatus(kind, text) {
  els.status.className = `status status-${kind}`;
  els.statusText.textContent = text;
}

let pyodideReadyPromise = null;
let runReport = null; // the proxied Python callable, once ready

async function initPyodide() {
  setStatus("loading", "Booting Python runtime…");
  const pyodide = await loadPyodide();

  setStatus("loading", "Loading agentgauge…");
  pyodide.FS.mkdirTree("/vendor/agentgauge/rules");
  for (const relPath of VENDOR_FILES) {
    const resp = await fetch(`vendor/${relPath}`);
    if (!resp.ok) {
      throw new Error(`failed to fetch ${relPath}: HTTP ${resp.status}`);
    }
    const text = await resp.text();
    pyodide.FS.writeFile(`/vendor/${relPath}`, text);
  }

  pyodide.runPython(`
import sys, json
sys.path.insert(0, "/vendor")

from agentgauge.astutils import FileContext
from agentgauge.scoring import score_contexts

def _run_report(source):
    try:
        ctx = FileContext.from_source(source, path="playground.py")
        report = score_contexts([ctx])
        return json.dumps({"ok": True, "report": report.to_dict()})
    except SyntaxError as exc:
        return json.dumps({
            "ok": False,
            "error": f"Syntax error at line {exc.lineno}: {exc.msg}",
        })
    except (RecursionError, MemoryError) as exc:
        return json.dumps({
            "ok": False,
            "error": f"{type(exc).__name__}: this input is too deeply "
                     "nested/large for the in-browser parser to handle.",
        })
    except Exception as exc:
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
`);

  runReport = pyodide.globals.get("_run_report");
  setStatus("ready", "Ready");
  els.scanBtn.disabled = false;
  return pyodide;
}

function getPyodide() {
  if (!pyodideReadyPromise) {
    pyodideReadyPromise = initPyodide().catch((err) => {
      setStatus("error", "Failed to load");
      showError(`Could not start the in-browser Python runtime: ${err.message}`);
      throw err;
    });
  }
  return pyodideReadyPromise;
}

function showEmpty() {
  els.emptyState.hidden = false;
  els.errorState.hidden = true;
  els.report.hidden = true;
}

function showError(message) {
  els.emptyState.hidden = true;
  els.errorState.hidden = false;
  els.report.hidden = true;
  els.errorMessage.textContent = message;
}

function showReport(report) {
  els.emptyState.hidden = true;
  els.errorState.hidden = true;
  els.report.hidden = false;

  els.verdictBadge.textContent = report.verdict;
  els.verdictBadge.className = `verdict-badge verdict-${report.verdict}`;
  els.scoreValue.textContent = report.score.toFixed(1);
  els.maxScoreValue.textContent = report.max_score;

  els.categories.innerHTML = "";
  for (const cat of report.categories) {
    const row = document.createElement("div");
    row.className = "category-row";

    const pct = cat.sites === 0 ? 100 : (cat.passed / cat.sites) * 100;
    const zeroSites = cat.sites === 0;

    row.innerHTML = `
      <span class="category-name">${escapeHtml(cat.name)}</span>
      <span class="category-bar-track">
        <span class="category-bar-fill${zeroSites ? " zero-sites" : ""}" style="width:${pct}%"></span>
      </span>
      <span class="category-score">${cat.score.toFixed(1)} / ${cat.weight}</span>
      ${zeroSites ? '<span class="category-note">no applicable sites in this file</span>' : ""}
    `;
    els.categories.appendChild(row);
  }

  if (report.warnings && report.warnings.length) {
    els.warnings.hidden = false;
    els.warnings.innerHTML =
      "<strong>Warnings</strong><ul>" +
      report.warnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("") +
      "</ul>";
  } else {
    els.warnings.hidden = true;
    els.warnings.innerHTML = "";
  }

  els.findingsCount.textContent = report.findings.length;
  els.findings.innerHTML = "";
  if (report.findings.length === 0) {
    const li = document.createElement("li");
    li.className = "finding";
    li.textContent = "No findings — every applicable site passed.";
    els.findings.appendChild(li);
  } else {
    for (const f of report.findings) {
      const li = document.createElement("li");
      li.className = `finding${f.critical ? " critical" : ""}`;
      li.innerHTML = `
        <div class="finding-loc">
          <span>${escapeHtml(f.file)}:${f.line}</span>
          <span class="rule-badge">${escapeHtml(f.rule)}</span>
          ${f.critical ? '<span class="critical-badge">critical</span>' : ""}
        </div>
        <div class="finding-message">${escapeHtml(f.message)}</div>
        <div class="finding-fix">fix: ${escapeHtml(f.fix)}</div>
      `;
      els.findings.appendChild(li);
    }
  }
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

async function scan() {
  const source = els.source.value;
  if (!source.trim()) {
    showEmpty();
    return;
  }
  if (source.length > MAX_SOURCE_CHARS) {
    showError(
      `That's ${source.length.toLocaleString()} characters -- this demo caps ` +
      `pasted input at ${MAX_SOURCE_CHARS.toLocaleString()} to keep the tab responsive. ` +
      "The real CLI has no such limit (just a 5 MB per-file cap)."
    );
    return;
  }

  els.scanBtn.disabled = true;
  els.editorHint.textContent = "Scanning…";
  try {
    await getPyodide();
    const resultJson = runReport(source);
    const result = JSON.parse(resultJson);
    if (result.ok) {
      showReport(result.report);
    } else {
      showError(result.error);
    }
  } catch (err) {
    showError(`Unexpected error: ${err.message}`);
  } finally {
    els.scanBtn.disabled = false;
    els.editorHint.textContent = "";
  }
}

async function loadSample(key) {
  const path = SAMPLES[key];
  if (!path) return;
  els.editorHint.textContent = "Loading example…";
  try {
    const resp = await fetch(path);
    const text = await resp.text();
    els.source.value = text;
    await scan();
  } finally {
    els.editorHint.textContent = "";
  }
}

document.querySelectorAll(".example-btn").forEach((btn) => {
  btn.addEventListener("click", () => loadSample(btn.dataset.sample));
});
els.scanBtn.addEventListener("click", scan);

// Boot Pyodide immediately so it's likely ready by the time someone
// finishes reading the page and pastes their own code.
getPyodide();
