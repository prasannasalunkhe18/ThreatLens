from threatlens.discovery.semgrep_scan import (
    _cwes_from_metadata,
    _is_scannable,
    _normalize_semgrep_path,
    parse_semgrep_json,
)

SAMPLE = {
    "results": [
        {
            "check_id": "python.lang.security.audit.formatted-sql-query",
            "path": "app/db.py",
            "start": {"line": 42},
            "extra": {
                "message": "Detected string formatting in a SQL statement.",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-89: SQL Injection"]},
            },
        },
        {
            "check_id": "generic.secrets.hardcoded",
            "path": "app/config.py",
            "start": {"line": 7},
            "extra": {
                "message": "Hardcoded secret",
                "severity": "WARNING",
                "metadata": {},  # no CWE
            },
        },
    ]
}


def test_parse_semgrep_json_maps_fields():
    findings = parse_semgrep_json(SAMPLE)
    assert len(findings) == 2

    f1 = findings[0]
    assert f1.finding_id == "F1"
    assert f1.cwe_ids == ["CWE-89"]
    assert f1.file == "app/db.py"
    assert f1.line == 42
    assert f1.rule_id.endswith("formatted-sql-query")
    assert f1.severity == "ERROR"

    f2 = findings[1]
    assert f2.finding_id == "F2"
    assert f2.cwe_ids == []  # no CWE metadata -> empty, still a finding


def test_normalize_semgrep_strips_docker_src_prefix():
    assert _normalize_semgrep_path("/src/core/appHandler.js") == "core/appHandler.js"
    assert _normalize_semgrep_path("core/appHandler.js") == "core/appHandler.js"


def test_parse_empty_results():
    assert parse_semgrep_json({"results": []}) == []
    assert parse_semgrep_json({}) == []


def test_cwes_from_metadata_variants():
    assert _cwes_from_metadata({"cwe": "CWE-79: XSS"}) == ["CWE-79"]
    assert _cwes_from_metadata({"cwe": ["CWE-89", "CWE-943"]}) == ["CWE-89", "CWE-943"]
    assert _cwes_from_metadata({"cwe": "89"}) == ["CWE-89"]
    assert _cwes_from_metadata({}) == []


def test_is_scannable():
    assert _is_scannable("routes/login.ts")
    assert _is_scannable("app/db.py")
    assert not _is_scannable("package-lock.json")
    assert not _is_scannable("logo.png")
