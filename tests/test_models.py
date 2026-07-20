from threatlens.models import InvestigationResult, Threat, ThreatModel


def test_threat_model_roundtrip():
    tm = ThreatModel(
        pr_summary="Adds raw SQL",
        threats=[
            Threat(
                threat_id="T1",
                name="SQL injection",
                description="User input concatenated into query",
                cwe_ids=["CWE-89"],
                investigate=True,
            )
        ],
    )
    data = tm.model_dump()
    assert ThreatModel.model_validate(data).threats[0].cwe_ids == ["CWE-89"]


def test_investigation_result_bounds():
    result = InvestigationResult(
        threat_id="T1",
        verdict="TRUE_POSITIVE",
        confidence=8,
        reasoning_chain=["unsanitized input", "reaches DB"],
    )
    assert result.verdict == "TRUE_POSITIVE"
