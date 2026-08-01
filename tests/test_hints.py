from threatlens.hints import hints_for_cwes


def test_hints_for_known_cwes():
    hints = hints_for_cwes(["CWE-918", "CWE-89"])
    assert any("proxy" in h.lower() or "private" in h.lower() or "redirect" in h.lower() for h in hints)
    assert any("parameterized" in h.lower() for h in hints)


def test_unknown_cwe_has_no_hints_but_is_ok():
    assert hints_for_cwes(["CWE-9999"]) == []
    assert hints_for_cwes([]) == []


def test_hints_dedupe():
    hints = hints_for_cwes(["CWE-89", "CWE-89"])
    assert len(hints) == len(set(hints))
