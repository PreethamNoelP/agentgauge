from agentgauge.astutils import FileContext
from agentgauge.rules import validation


def run(src: str):
    return validation.check(FileContext.from_source(src, path="mem.py"))


def test_raw_risky_param_fails():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def read(path):\n"
        "    return open(path).read()\n"
    )
    assert (sites, passed) == (1, 0)
    assert "'path'" in findings[0].message


def test_prefix_check_passes():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def read(path):\n"
        "    if not path.startswith('/data/'):\n"
        "        raise ValueError('outside sandbox')\n"
        "    return open(path).read()\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_sanitizer_call_passes():
    sites, passed, _ = run(
        "@mcp.tool()\n"
        "def sh(cmd):\n"
        "    safe = shlex.quote(cmd)\n"
        "    return subprocess.run(safe, shell=False)\n"
    )
    assert (sites, passed) == (1, 1)


def test_each_risky_param_is_its_own_site():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def go(url, query):\n"
        "    validate_url(url)\n"
        "    return http.get(url, query)\n"
    )
    assert (sites, passed) == (2, 1)  # url validated, query not
    assert "'query'" in findings[0].message


def test_safe_param_names_are_not_sites():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def add(a, b):\n"
        "    return a + b\n"
    )
    assert (sites, passed, findings) == (0, 0, [])


def test_non_tool_function_is_ignored():
    # No tool decorator, no sensitive call -> rule doesn't apply.
    sites, passed, findings = run(
        "def helper(path):\n"
        "    return path.upper()\n"
    )
    assert (sites, passed, findings) == (0, 0, [])
