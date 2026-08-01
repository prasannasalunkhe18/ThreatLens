"""Shared test helpers."""

from __future__ import annotations

import json


def evidence_json(
    threat_id: str,
    *,
    attacker_control: str = "confirmed",
    sink_reachability: str = "confirmed",
    runtime_reachability: str = "confirmed",
    mitigation_effectiveness: str = "refuted",
    changed_code_relevance: str = "likely",
    production_relevance: str = "likely",
    external_controls: str = "unknown",
    unresolved_questions: list[str] | None = None,
    reasoning_chain: list[str] | None = None,
) -> str:
    def item(key: str, status: str, summary: str = "assessed") -> dict:
        return {
            "key": key,
            "status": status,
            "summary": summary,
            "evidence": [],
            "source": "llm_inference",
        }

    return json.dumps(
        {
            "threat_id": threat_id,
            "attacker_control": item("attacker_control", attacker_control),
            "sink_reachability": item("sink_reachability", sink_reachability),
            "runtime_reachability": item("runtime_reachability", runtime_reachability),
            "mitigation_effectiveness": item(
                "mitigation_effectiveness", mitigation_effectiveness
            ),
            "changed_code_relevance": item(
                "changed_code_relevance", changed_code_relevance
            ),
            "production_relevance": item("production_relevance", production_relevance),
            "external_controls": item("external_controls", external_controls),
            "unresolved_questions": unresolved_questions or [],
            "reasoning_chain": reasoning_chain
            or ["source identified", "sink reached", "conclusion"],
        }
    )
