from threatlens.discovery.codeql_scan import _cwe_from_tag, parse_sarif_json
from threatlens.discovery.fuse import fuse_findings
from threatlens.models import Finding

SARIF = {
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "rules": [
                        {
                            "id": "js/sql-injection",
                            "properties": {"tags": ["security", "external/cwe/cwe-089"]},
                        },
                        {
                            "id": "js/request-forgery",
                            "properties": {"tags": ["external/cwe/cwe-918"]},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "js/sql-injection",
                    "message": {"text": "User input flows to SQL."},
                    "level": "error",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/db.js"},
                                "region": {"startLine": 12},
                            }
                        }
                    ],
                },
                {
                    "rule": {"index": 1},  # reference by index, no ruleId
                    "message": {"text": "SSRF"},
                    "level": "warning",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/fetch.js"},
                                "region": {"startLine": 20},
                            }
                        }
                    ],
                },
            ],
        }
    ]
}


def test_cwe_from_tag():
    assert _cwe_from_tag("external/cwe/cwe-079") == "CWE-79"
    assert _cwe_from_tag("external/cwe/cwe-918") == "CWE-918"
    assert _cwe_from_tag("security") is None


def test_parse_sarif_maps_fields_and_cwes():
    findings = parse_sarif_json(SARIF)
    assert len(findings) == 2
    f1 = findings[0]
    assert f1.finding_id == "C1"
    assert f1.cwe_ids == ["CWE-89"]
    assert f1.file == "src/db.js"
    assert f1.line == 12
    assert f1.source == "codeql"
    # second result resolved its rule by index -> SSRF CWE
    assert findings[1].cwe_ids == ["CWE-918"]
    assert findings[1].rule_id == "js/request-forgery"


def test_parse_empty_sarif():
    assert parse_sarif_json({"runs": []}) == []
    assert parse_sarif_json({}) == []


def test_fuse_dedups_overlap_and_unions_sources():
    codeql = [
        Finding(finding_id="C1", cwe_ids=["CWE-918"], file="src/fetch.js", line=20,
                rule_id="js/ssrf", source="codeql"),
    ]
    semgrep = [
        # same sink/CWE, different path prefix + rule -> should merge
        Finding(finding_id="F1", cwe_ids=["CWE-918"], file="/src/fetch.js", line=20,
                rule_id="javascript.express.ssrf", source="semgrep"),
        # distinct finding -> kept
        Finding(finding_id="F2", cwe_ids=["CWE-79"], file="src/view.js", line=5,
                rule_id="xss", source="semgrep"),
    ]
    fused = fuse_findings(codeql, semgrep)
    assert len(fused) == 2
    merged = next(f for f in fused if f.line == 20)
    assert merged.source == "codeql+semgrep"
    assert "js/ssrf" in merged.rule_id and "javascript.express.ssrf" in merged.rule_id
    # ids re-numbered F1..Fn
    assert [f.finding_id for f in fused] == ["F1", "F2"]


def test_fuse_no_merge_when_cwes_differ():
    a = [Finding(finding_id="C1", cwe_ids=["CWE-89"], file="x.js", line=1, source="codeql")]
    b = [Finding(finding_id="F1", cwe_ids=["CWE-918"], file="x.js", line=1, source="semgrep")]
    fused = fuse_findings(a, b)
    assert len(fused) == 2


def test_fuse_merges_within_line_window():
    # Same file + CWE, reported 1 line apart by each tool (real-world offset).
    codeql = [Finding(finding_id="C1", cwe_ids=["CWE-918"], file="routes/x.js", line=15,
                      rule_id="js/request-forgery", source="codeql")]
    semgrep = [Finding(finding_id="F1", cwe_ids=["CWE-918"], file="routes/x.js", line=16,
                       rule_id="javascript.express.ssrf", source="semgrep")]
    fused = fuse_findings(codeql, semgrep)
    assert len(fused) == 1
    assert fused[0].source == "codeql+semgrep"


def test_fuse_no_merge_outside_line_window():
    a = [Finding(finding_id="C1", cwe_ids=["CWE-918"], file="x.js", line=10, source="codeql")]
    b = [Finding(finding_id="F1", cwe_ids=["CWE-918"], file="x.js", line=99, source="semgrep")]
    assert len(fuse_findings(a, b)) == 2
