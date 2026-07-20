"""Skill registry — deterministic CWE -> skill lookup, no LLM."""

from __future__ import annotations

from pathlib import Path

import yaml

from threatlens.models import Skill

DEFAULT_SKILLS_DIR = Path(__file__).resolve().parents[3] / "skills"


def _normalize_checklist_item(item: object) -> str:
    """Coerce a checklist entry back to a string.

    YAML parses an unquoted sequence line containing ``: `` as a mapping
    (``- trace it: name each hop`` -> ``{'trace it': 'name each hop'}``).
    Rebuild the original prose instead of forcing skill authors to quote every
    colon.
    """
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        parts = []
        for key, value in item.items():
            parts.append(f"{key}: {value}" if value is not None else f"{key}:")
        return " ".join(parts)
    return str(item)


def _normalize_skill_data(data: dict) -> dict:
    checklist = data.get("checklist")
    if isinstance(checklist, list):
        data["checklist"] = [_normalize_checklist_item(i) for i in checklist]
    return data


class SkillRegistry:
    def __init__(self, skills: list[Skill]):
        self.skills = skills
        self._by_cwe: dict[str, Skill] = {}
        for skill in skills:
            for cwe in skill.cwe_ids:
                self._by_cwe[cwe.upper()] = skill

    @classmethod
    def load(cls, skills_dir: Path | None = None) -> SkillRegistry:
        directory = skills_dir or DEFAULT_SKILLS_DIR
        skills = []
        for path in sorted(directory.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            skills.append(Skill.model_validate(_normalize_skill_data(data)))
        return cls(skills)

    def match(self, cwe_ids: list[str]) -> Skill | None:
        """Return the first skill covering any of the threat's CWEs."""
        for cwe in cwe_ids:
            skill = self._by_cwe.get(cwe.upper())
            if skill:
                return skill
        return None

    @property
    def covered_cwes(self) -> set[str]:
        return set(self._by_cwe)
