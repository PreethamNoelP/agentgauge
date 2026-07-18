from agentgauge.astutils import FileContext
from agentgauge.rules import oversight


def run(src: str):
    return oversight.check(FileContext.from_source(src, path="mem.py"))


def test_unguarded_sensitive_call_fails():
    sites, passed, findings = run(
        "import shutil\n"
        "def wipe(path):\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)
    assert len(findings) == 1
    assert findings[0].line == 3
    assert "file delete" in findings[0].message


def test_guard_clause_approval_passes():
    # The dangerous call is NOT inside the if -- guard-clause style.
    sites, passed, findings = run(
        "def wipe(path):\n"
        "    if not request_approval('wipe', path):\n"
        "        return\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_approval_decorator_passes():
    sites, passed, _ = run(
        "@requires_human_approval\n"
        "def wipe(path):\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)


def test_builtin_input_counts_as_oversight():
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    answer = input('really? ')\n"
        "    if answer == 'y':\n"
        "        shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)


def test_no_sensitive_calls_means_no_sites():
    sites, passed, findings = run("def add(a, b):\n    return a + b\n")
    assert (sites, passed, findings) == (0, 0, [])


def test_known_limitation_mention_without_enforcement_still_passes():
    # Documented gap: the heuristic is presence-based. An approval variable
    # that never gates anything still passes. Catching this needs data-flow
    # analysis; v1 accepts the false pass. If we ever add flow analysis,
    # flipping this test's expectation is the definition of done.
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    approved = False\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)
