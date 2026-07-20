import json

from threatlens.github_client import PRFile, PullRequest
from threatlens.pipeline import run_pipeline
from threatlens.skills.registry import SkillRegistry
from threatlens.stages.investigate import build_investigation_prompt
from threatlens.models import Skill, Threat


def make_pr() -> PullRequest:
    return PullRequest(
        owner="acme",
        repo="app",
        number=1,
        title="Add user search",
        body="",
        author="bob",
        base_ref="main",
        head_ref="feat",
        html_url="https://github.com/acme/app/pull/1",
        diff=(
            "diff --git a/search.py b/search.py\n"
            "+q = request.args['q']\n"
            "+cursor.execute(f\"SELECT * FROM users WHERE name = '{q}'\")\n"
        ),
        files=[PRFile(filename="search.py", status="added")],
        commits_summary=["abc1234 add search"],
    )


class ScriptedProvider:
    """Returns queued responses in order."""

    name = "scripted"

    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.prompts: list[str] = []

    def complete(self, prompt: str, *, system: str | None = None) -> str:
        self.prompts.append(prompt)
        return self.responses.pop(0)


STAGE1_RESPONSE = json.dumps(
    {
        "pr_summary": "Adds user search with f-string SQL.",
        "threats": [
            {
                "threat_id": "T1",
                "name": "SQL injection in search",
                "description": "q flows into f-string SQL in search.py",
                "cwe_ids": ["CWE-89"],
                "investigate": True,
            },
            {
                "threat_id": "T2",
                "name": "Generic worry",
                "description": "not worth it",
                "cwe_ids": [],
                "investigate": False,
            },
        ],
    }
)

STAGE2_RESPONSE = json.dumps(
    {
        "threat_id": "T1",
        "verdict": "TRUE_POSITIVE",
        "confidence": 9,
        "reasoning_chain": [
            "source: request.args['q'] in search.py",
            "sink: cursor.execute f-string, no parameterization",
            "conclusion: reachable SQLi",
        ],
    }
)


def test_pipeline_investigates_only_flagged_threats():
    provider = ScriptedProvider([STAGE1_RESPONSE, STAGE2_RESPONSE])
    registry = SkillRegistry.load()
    report = run_pipeline(make_pr(), provider, registry, gh=None, discovery="llm")

    assert report.discovery == "llm"
    assert len(report.threat_model.threats) == 2
    assert len(report.investigations) == 1  # only T1 flagged
    inv = report.investigations[0]
    assert inv.threat_id == "T1"
    assert inv.verdict == "TRUE_POSITIVE"
    assert report.skill_matches["T1"].startswith("Injection")
    assert inv.skill_used.startswith("Injection")
    # Investigation prompt must contain the skill checklist and the diff
    assert "Checklist" in provider.prompts[1]
    assert "search.py" in provider.prompts[1]


def test_pipeline_stage1_only():
    provider = ScriptedProvider([STAGE1_RESPONSE])
    registry = SkillRegistry.load()
    report = run_pipeline(
        make_pr(), provider, registry, gh=None, discovery="llm", investigate=False
    )
    assert report.investigations == []


def test_investigation_prompt_without_skill():
    threat = Threat(
        threat_id="T9",
        name="Weird thing",
        description="odd",
        cwe_ids=["CWE-9999"],
        investigate=True,
    )
    prompt = build_investigation_prompt(make_pr(), threat, None, "")
    assert "GENERIC" in prompt
    assert "source" in prompt.lower()


def test_investigation_prompt_includes_reachability():
    registry = SkillRegistry.load()
    skill: Skill = registry.match(["CWE-89"])
    threat = Threat(
        threat_id="T1",
        name="SQLi",
        description="d",
        cwe_ids=["CWE-89"],
        investigate=True,
    )
    prompt = build_investigation_prompt(make_pr(), threat, skill, "file ctx here")
    assert "Reachability definition" in prompt
    assert "file ctx here" in prompt
