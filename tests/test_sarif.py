from agentgauge.astutils import FileContext
from agentgauge.sarif import build_sarif
from agentgauge.scoring import ALL_RULES, score_contexts


def ctx(src: str, path: str = "mem.py") -> FileContext:
    return FileContext.from_source(src, path=path)


def test_sarif_has_one_rule_descriptor_per_registered_rule():
    report = score_contexts([ctx("x = 1\n")])
    sarif = build_sarif(report)
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {rule.RULE_ID for rule in ALL_RULES}


def test_sarif_result_maps_critical_finding_to_error_level():
    report = score_contexts([ctx("def wipe(path):\n    shutil.rmtree(path)\n")])
    sarif = build_sarif(report)
    results = sarif["runs"][0]["results"]
    oversight_result = next(r for r in results if r["ruleId"] == "human-oversight")
    assert oversight_result["level"] == "error"


def test_sarif_result_maps_non_critical_finding_to_warning_level():
    report = score_contexts([ctx("auto_approve = True\n")])
    sarif = build_sarif(report)
    results = sarif["runs"][0]["results"]
    assert results[0]["level"] == "warning"


def test_sarif_result_location_has_file_and_line():
    report = score_contexts([ctx("auto_approve = True\n", "flags.py")])
    sarif = build_sarif(report)
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "flags.py"
    assert location["region"]["startLine"] == 1


def test_sarif_clean_scan_has_no_results():
    report = score_contexts([ctx("def add(a, b):\n    return a + b\n")])
    sarif = build_sarif(report)
    assert sarif["runs"][0]["results"] == []


def test_sarif_run_properties_carry_score_and_verdict():
    report = score_contexts([ctx("def add(a, b):\n    return a + b\n")])
    sarif = build_sarif(report)
    props = sarif["runs"][0]["properties"]
    assert props == {"score": 100.0, "maxScore": 100, "verdict": "PASS"}


def test_sarif_version_and_schema_are_2_1_0():
    report = score_contexts([ctx("x = 1\n")])
    sarif = build_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
