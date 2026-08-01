import json

from conftest import evidence_json
from threatlens.github_client import PRFile, PullRequest
from threatlens.models import Threat
from threatlens.pipeline import run_pipeline
from threatlens.stages.investigate import build_investigation_prompt
from threatlens.verdict import Verdict


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

STAGE2_RESPONSE = evidence_json("T1")


def test_pipeline_investigates_only_flagged_threats():
    provider = ScriptedProvider([STAGE1_RESPONSE, STAGE2_RESPONSE])
    report = run_pipeline(make_pr(), provider, None, gh=None, discovery="llm")

    assert report.discovery == "llm"
    assert len(report.threat_model.threats) == 2
    assert len(report.investigations) == 1  # only T1 flagged
    inv = report.investigations[0]
    assert inv.threat_id == "T1"
    assert inv.verdict == Verdict.CONFIRMED
    assert report.investigators["T1"] == "evidence_investigator_v1"
    assert inv.investigator == "evidence_investigator_v1"
    assert "evidence_investigator_v1" in provider.prompts[1]
    assert "search.py" in provider.prompts[1]


def test_pipeline_stage1_only():
    provider = ScriptedProvider([STAGE1_RESPONSE])
    report = run_pipeline(
        make_pr(), provider, None, gh=None, discovery="llm", investigate=False
    )
    assert report.investigations == []


def test_investigation_prompt_without_hints():
    threat = Threat(
        threat_id="T9",
        name="Weird thing",
        description="odd",
        cwe_ids=["CWE-9999"],
        investigate=True,
    )
    prompt = build_investigation_prompt(make_pr(), threat, "")
    assert "evidence_investigator_v1" in prompt
    assert "attacker" in prompt.lower() or "source" in prompt.lower()


def test_investigation_prompt_includes_optional_hints():
    threat = Threat(
        threat_id="T1",
        name="SQLi",
        description="d",
        cwe_ids=["CWE-89"],
        investigate=True,
    )
    prompt = build_investigation_prompt(make_pr(), threat, "file ctx here")
    assert "Optional vulnerability-specific hints" in prompt
    assert "parameterized" in prompt.lower()
    assert "file ctx here" in prompt
