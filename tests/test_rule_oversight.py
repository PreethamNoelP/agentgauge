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


def test_dead_approval_variable_no_longer_grants_a_false_pass():
    # Formerly a documented false pass: a name merely mentioning approval
    # vocabulary satisfied the rule even if nothing ever checked it. Fixed
    # by requiring an *enforcing position* (call, if/while/assert test, or
    # decorator) -- a bare assignment no one reads is none of those.
    sites, passed, findings = run(
        "def wipe(path):\n"
        "    approved = False\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)
    assert len(findings) == 1


def test_keyword_argument_named_like_approval_does_not_pass():
    # "require_approval=False" passed to an unrelated call used to satisfy
    # this rule on vocabulary alone (rule 6 catches the polarity). Only the
    # callee's own name counts now, not the names of its keyword arguments.
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    configure(require_approval=False)\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)


def test_if_test_naming_approval_passes():
    # The vocabulary sits in the if's *test*, not in a dead assignment --
    # an enforcing position even though the tested name is a bare Name,
    # not a call.
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    approved = check_policy()\n"
        "    if approved:\n"
        "        shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)


def test_assert_naming_approval_passes():
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    assert approved\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)
