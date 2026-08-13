from agentgauge.astutils import FileContext
from agentgauge.config import RuleConfig
from agentgauge.rules import validation


def run(src: str, config: RuleConfig | None = None):
    return validation.check(FileContext.from_source(src, path="mem.py", config=config))


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


def test_literal_annotation_counts_as_validation():
    # A closed set of allowed values is validation by construction -- the
    # documented "highest-value v2 improvement" from RULES.md.
    sites, passed, findings = run(
        "from typing import Literal\n"
        "@mcp.tool()\n"
        "def read(path: Literal['a', 'b']):\n"
        "    return open(path).read()\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_annotated_field_counts_as_validation():
    sites, passed, findings = run(
        "from typing import Annotated\n"
        "from pydantic import Field\n"
        "@mcp.tool()\n"
        "def query(query: Annotated[str, Field(pattern=r'^SELECT')]):\n"
        "    return db.execute(query)\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_annotated_without_field_does_not_count_as_validation():
    # Annotated[T, ...] alone carries no declared constraint -- only a
    # Field(...) call in the metadata is evidence.
    sites, passed, findings = run(
        "from typing import Annotated\n"
        "@mcp.tool()\n"
        "def query(query: Annotated[str, 'some docstring metadata']):\n"
        "    return db.execute(query)\n"
    )
    assert (sites, passed) == (1, 0)


def test_plain_str_annotation_does_not_count_as_validation():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def read(path: str):\n"
        "    return open(path).read()\n"
    )
    assert (sites, passed) == (1, 0)


def test_extra_risky_param_from_config_is_a_site():
    config = RuleConfig(risky_param_tokens=frozenset({"apikey"}))
    sites, passed, findings = run(
        "@mcp.tool()\ndef configure(apikey):\n    store(apikey)\n",
        config=config,
    )
    assert (sites, passed) == (1, 0)


def test_extra_validation_token_from_config_passes():
    config = RuleConfig(validation_tokens=frozenset({"scrub"}))
    sites, passed, _ = run(
        "@mcp.tool()\ndef read(path):\n    scrub(path)\n    return open(path).read()\n",
        config=config,
    )
    assert (sites, passed) == (1, 1)
