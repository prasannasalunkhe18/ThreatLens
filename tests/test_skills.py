from pathlib import Path

from threatlens.skills.registry import (
    DEFAULT_SKILLS_DIR,
    SkillRegistry,
    _normalize_checklist_item,
)


def test_loads_all_four_skills():
    registry = SkillRegistry.load()
    assert len(registry.skills) == 4
    names = {s.name for s in registry.skills}
    assert any("Injection" in n for n in names)
    assert any("Auth" in n for n in names)
    assert any("Forgery" in n for n in names)
    assert any("Deserialization" in n for n in names)


def test_match_by_cwe():
    registry = SkillRegistry.load()
    assert "CWE-89" in registry.match(["CWE-89"]).cwe_ids
    assert registry.match(["CWE-918"]).name.startswith("Server-Side")
    assert registry.match(["CWE-502"]) is not None
    assert registry.match(["CWE-287"]) is not None
    # SSTI maps into the injection skill
    assert registry.match(["CWE-94"]).name.startswith("Injection")


def test_match_unknown_cwe_returns_none():
    registry = SkillRegistry.load()
    assert registry.match(["CWE-9999"]) is None
    assert registry.match([]) is None


def test_skills_have_reachability_and_checklist():
    registry = SkillRegistry.load()
    for skill in registry.skills:
        assert skill.reachability.strip(), f"{skill.name} missing reachability"
        assert len(skill.checklist) >= 5, f"{skill.name} checklist too short"


def test_skills_are_principle_based():
    """v2: each skill declares generic source/sink/mitigation definitions."""
    registry = SkillRegistry.load()
    for skill in registry.skills:
        assert skill.source_definition.strip(), f"{skill.name} missing source_definition"
        assert skill.sink_definition.strip(), f"{skill.name} missing sink_definition"
        assert skill.mitigation_patterns, f"{skill.name} missing mitigation_patterns"


def test_skills_dir_exists():
    assert DEFAULT_SKILLS_DIR.is_dir()
    assert list(Path(DEFAULT_SKILLS_DIR).glob("*.yaml"))


def test_normalize_checklist_item_handles_unquoted_colon():
    # YAML parses "- trace it: name each hop" as a dict — rebuild the prose
    assert _normalize_checklist_item({"trace it": "name each hop"}) == (
        "trace it: name each hop"
    )
    assert _normalize_checklist_item({"dangling key": None}) == "dangling key:"
    assert _normalize_checklist_item("already a string") == "already a string"


def test_registry_loads_skill_with_unquoted_colon(tmp_path):
    skill_yaml = (
        "name: Test\n"
        'cwe_ids: ["CWE-1"]\n'
        "reachability: reachable when input hits sink\n"
        "checklist:\n"
        "  - Identify the source of the value then map it to the sink\n"
        "  - SQL: is the query parameterized or concatenated on this path?\n"
        "  - Command: does the value reach a shell?\n"
        "  - Check exposure: is the route registered and reachable?\n"
        "  - Decide verdict based on reachability of the tainted path\n"
    )
    (tmp_path / "test.yaml").write_text(skill_yaml, encoding="utf-8")
    registry = SkillRegistry.load(tmp_path)
    skill = registry.match(["CWE-1"])
    assert skill is not None
    assert all(isinstance(item, str) for item in skill.checklist)
    assert any(item.startswith("SQL: ") for item in skill.checklist)
    assert any(item.startswith("Command: ") for item in skill.checklist)
