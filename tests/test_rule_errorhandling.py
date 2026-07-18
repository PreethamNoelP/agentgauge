from agentgauge.astutils import FileContext
from agentgauge.rules import errorhandling


def run(src: str):
    return errorhandling.check(FileContext.from_source(src, path="mem.py"))


def test_while_true_without_exit_fails():
    sites, passed, findings = run(
        "def poll_forever():\n"
        "    while True:\n"
        "        poll()\n"
    )
    assert (sites, passed) == (1, 0)
    assert findings[0].line == 2
    assert "while True" in findings[0].message


def test_while_true_with_break_passes():
    sites, passed, findings = run(
        "while True:\n"
        "    if done():\n"
        "        break\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_break_in_nested_loop_does_not_count():
    # The break exits the inner for-loop; the outer while True never ends.
    # A naive "subtree contains a break" check would wrongly pass this.
    sites, passed, _ = run(
        "while True:\n"
        "    for item in queue:\n"
        "        if item.stop:\n"
        "            break\n"
    )
    assert (sites, passed) == (1, 0)


def test_return_inside_while_true_passes():
    sites, passed, _ = run(
        "def wait():\n"
        "    while True:\n"
        "        if ready():\n"
        "            return True\n"
    )
    assert (sites, passed) == (1, 1)


def test_sensitive_call_wrapped_in_try_passes():
    sites, passed, findings = run(
        "def wipe(path):\n"
        "    try:\n"
        "        shutil.rmtree(path)\n"
        "    except OSError:\n"
        "        logger.error('failed')\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_unwrapped_sensitive_call_fails():
    sites, passed, findings = run(
        "def wipe(path):\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)
    assert "try/except" in findings[0].message


def test_call_in_except_handler_is_not_protected():
    # The rmtree lives in the handler -- the try protects prepare(), not it.
    # A naive "has a Try ancestor" check would wrongly pass this.
    sites, passed, _ = run(
        "def cleanup(path):\n"
        "    try:\n"
        "        prepare()\n"
        "    except Exception:\n"
        "        shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)


def test_loop_and_call_sites_both_counted():
    sites, passed, _ = run(
        "def worker(path):\n"
        "    while True:\n"
        "        poll()\n"
        "    try:\n"
        "        shutil.rmtree(path)\n"
        "    except OSError:\n"
        "        pass\n"
    )
    assert (sites, passed) == (2, 1)  # loop fails, wrapped call passes


def test_no_sites_in_benign_code():
    sites, passed, findings = run("def add(a, b):\n    return a + b\n")
    assert (sites, passed, findings) == (0, 0, [])
