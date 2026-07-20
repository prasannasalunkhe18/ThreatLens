# Plan: ThreatLens — PR Vulnerability Triage Agent

## Week 1 — Foundation + Stage 1
- [x] Repo scaffold (package structure, pyproject.toml, pytest setup)
- [x] GitHub API client: fetch PR diff, changed files, commit metadata
- [x] Provider abstraction: OpenRouter (free-model fallback list) + Groq secondary, zero cost
- [x] Data models: `Threat`, `ThreatModel` (pydantic)
- [x] Stage 1 prompt: threat modeling on PR diff
- [x] CLI command: `threatlens pr analyze <PR_URL>` prints Stage 1 output only
- [x] Test against 5-10 real PRs, tune prompt until threat ID is reasonable (10-PR corpus, 10/10 pass — see eval/)
- **Deliverable:** CLI takes PR URL -> prints threat model JSON


## Week 2 — Stage 2 (Investigation Skills)
- [x] Skill schema defined (own format, CWE-mapped checklist + reachability)
- [x] Write 4 skills: injection (89/78/79/94), auth (287/306), SSRF (918), deserialization (502)
- [x] Skill registry + lookup logic (Stage 1 CWE output -> matched skill)
- [x] Data models: `InvestigationResult`
- [x] Stage 2 prompt: investigation using matched skill checklist
- [x] Wire Stage 1 -> Stage 2 pipeline end-to-end
- **Deliverable:** full 2-stage pipeline, PR in -> verdict out (DONE — Juice Shop #655 -> 2x TRUE_POSITIVE w/ traces; SQLi-fix PR -> no escalation)

## Week 3 — Verdict, Scoring, Polish
- [x] Confidence scoring heuristic finalized (1-10 rubric in Stage 2 prompt + README table)
- [x] Output formatter (JSON + readable markdown report — `report.py`, CLI `--format md`)
- [x] Error handling: API failures, rate limits, provider fallback triggering correctly (empty/truncated content now retryable, advances chain)
- [x] Cost/token/call logging (`usage.py`, threaded into PipelineReport + CLI)
- [x] Test suite against known-vulnerable sample PRs with pre-labeled expected verdicts (`eval/verdicts.yaml`, `scripts/run_verdict_eval.py` — 5/5 passing)
- [x] README with setup instructions
- [x] Architecture diagram (mermaid in README)
- [x] Written rationale doc: design decisions captured in journal + README confidence/architecture sections
- **Deliverable:** polished, demoable v1 (DONE)

## Week 4 — v2 architecture pivot: scanner-driven discovery + LLM verification
- [x] Semgrep discovery layer (`discovery/semgrep_scan.py`): materialize changed files, run `semgrep --json`, parse into `Finding`
- [x] Execution backend auto-detect: local `semgrep` binary, else `semgrep/semgrep` Docker (Windows-safe)
- [x] Keep v1 LLM discovery behind `--discovery=llm` for comparison
- [x] Generic fallback investigation prompt (`prompts/investigate_generic.md`) + `skill_used` field on `InvestigationResult`
- [x] Registry: skill match or generic fallback; **no finding dropped on a miss** (asserted by test)
- [x] Rewrite the 4 skills principle-based (`source_definition`, `sink_definition`, `mitigation_patterns`, ecosystem hints)
- [x] Pipeline wiring: `--discovery=semgrep` default; `--force-generic` for the comparison
- [x] Fork-aware file fetch (head repo + head SHA) — required for Semgrep to see real files
- [x] Re-validate labeled eval set under Semgrep (`scripts/run_verdict_eval.py`)
- [x] Skill-vs-generic accuracy comparison (`scripts/run_skill_vs_generic.py`)
- [x] Docs: design.md v2 architecture + principle-based skills + CodeQL-as-future; plan; journal pivot entry
- **Deliverable:** `threatlens pr analyze <URL>` discovers via Semgrep, investigates each finding with best skill or generic fallback, same report format, plus documented skill-vs-generic comparison.

## v3 — CodeQL as a second discovery source
- [x] `discovery/codeql_scan.py`: build DB + run `*-security-extended` suites, parse SARIF -> `Finding` (CWE from rule tags)
- [x] `discovery/fuse.py`: fuse Semgrep + CodeQL, de-dup on (file, CWE) within a line window; union `source` -> `codeql+semgrep`
- [x] `--discovery=semgrep|codeql|both|llm`; `scripts/setup_codeql.py` bundle installer; `.codeql/` git-ignored
- [x] Tests: SARIF parse, CWE-tag extraction, fusion/dedup (incl. line-window merge)
- **Deliverable:** live CodeQL taint analysis + fused discovery; proven on js655 (SSRF confirmed by both tools).

## v3.1 — HTML report UI
- [x] `render_html()` in `report.py`; wired as `threatlens pr analyze --format html -o report.html`
- [x] `scripts/render_report.py` to re-render any saved report JSON to standalone HTML
- [x] Single self-contained file (inline CSS/JS), flat/dense/technical, no framework/build
- [x] Signature interaction: expanding a finding reveals its source→sink→verdict trace with a restrained staggered reveal (respects `prefers-reduced-motion`)
- [x] Shows discovery mode, verdict/skill_used/source per finding (`codeql+semgrep` = higher-confidence), summary strip + usage
- [x] Local hosting: `--serve [--port --no-browser]` on analyze + `threatlens report serve <json>` — in-memory `http.server`, no file written
- **Deliverable:** open-locally HTML report built against the real `PipelineReport` schema, viewable as a file or served live.

## Week 5+ (still optional / deferred)
- [ ] Multi-repo / org-wide search support
- [ ] Additional skills / additional Semgrep rulesets
- [ ] Stress-test provider fallback under rate-limit conditions

## Milestones / Checkpoints
- End of Week 1: Stage 1 alone must produce sensible, non-generic threats on real PRs
- End of Week 2: Full pipeline runs without manual intervention
- End of Week 3: Demo-ready — can run live in an interview without surprises
- Before any interview: review `journal.md` to refresh on decisions made, so every part is explainable unprompted
