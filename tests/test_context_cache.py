"""The cached FileContext views must answer exactly what the uncached
primitives answer. They exist only so six rules asking the same question do
not walk the same subtrees a dozen times -- a performance change that
silently altered the site population would be far worse than a slow scan.
"""

from pathlib import Path

import pytest

from agentgauge.astutils import (
    FileContext,
    build_parent_map,
    is_tool_function,
    iter_functions,
    iter_sensitive_calls,
)

FIXTURES = Path(__file__).parent / "fixtures"

SHAPES = [
    "def plain():\n    return 1\n",
    "import shutil\ndef wipe(p):\n    shutil.rmtree(p)\n",
    "@mcp.tool()\ndef fetch(url):\n    return http.get(url)\n",
    # sink inside a nested def: both the inner and the outer function are
    # tool functions, because the outer one is what exposes the inner.
    "import os\ndef outer():\n    def inner(p):\n        os.remove(p)\n    return inner\n",
    # sink inside a method of a class inside a function
    "import os\ndef make():\n    class C:\n        def m(self, p):\n            os.remove(p)\n    return C\n",
    # async tool
    "import asyncio\nasync def run(c):\n    await asyncio.create_subprocess_shell(c)\n",
    # sink in a lambda
    "import os\nf = lambda p: os.remove(p)\n",
    # sink at module level only
    "import os\nos.system('x')\n",
    # aliased sink
    "from subprocess import run\n@tool\ndef go(cmd):\n    run(cmd)\n",
    # decorated but no sink
    "@app.tool\ndef ping():\n    return 'pong'\n",
]


@pytest.mark.parametrize("src", SHAPES)
def test_tool_functions_matches_is_tool_function(src):
    ctx = FileContext.from_source(src, path="mem.py")
    expected = {
        fn for fn in iter_functions(ctx.tree)
        if is_tool_function(fn, ctx.import_aliases)
    }
    assert ctx.tool_functions == expected


@pytest.mark.parametrize("src", SHAPES)
def test_cached_views_match_the_primitives(src):
    ctx = FileContext.from_source(src, path="mem.py")
    assert ctx.functions == list(iter_functions(ctx.tree))
    assert ctx.sensitive_calls == list(
        iter_sensitive_calls(ctx.tree, ctx.import_aliases)
    )
    assert ctx.parents == build_parent_map(ctx.tree)


@pytest.mark.parametrize("fixture", ["clean_server.py", "vulnerable_server.py"])
def test_cached_views_match_on_the_fixtures(fixture):
    ctx = FileContext.from_source(
        (FIXTURES / fixture).read_text(), path=fixture
    )
    expected = {
        fn for fn in iter_functions(ctx.tree)
        if is_tool_function(fn, ctx.import_aliases)
    }
    assert ctx.tool_functions == expected


def test_cached_views_are_computed_once():
    ctx = FileContext.from_source("import os\ndef f(p):\n    os.remove(p)\n")
    assert ctx.sensitive_calls is ctx.sensitive_calls
    assert ctx.parents is ctx.parents
    assert ctx.functions is ctx.functions


def test_parent_map_is_not_built_for_a_file_with_no_sinks():
    # The parent map is the largest allocation a scan makes (one dict entry
    # per AST node). Every question needing it starts from a sensitive call,
    # so a file without one must never pay for it.
    from agentgauge.scoring import score_contexts

    ctx = FileContext.from_source("def add(a, b):\n    return a + b\n", path="mem.py")
    score_contexts([ctx])

    assert "parents" not in ctx.__dict__


def test_parent_map_is_built_when_a_sink_exists():
    from agentgauge.scoring import score_contexts

    ctx = FileContext.from_source(
        "import os\ndef f(p):\n    os.remove(p)\n", path="mem.py"
    )
    score_contexts([ctx])

    assert "parents" in ctx.__dict__
