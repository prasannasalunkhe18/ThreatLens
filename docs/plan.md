# Plan: ThreatLens PR Vulnerability Triage Agent

## Week 1: Foundation + Stage 1
- [x] Repo scaffold (package structure, pyproject.toml, pytest setup)
- [x] GitHub API client: fetch PR diff, changed files, commit metadata
- [x] Provider abstraction: OpenRouter free models + Groq, zero cost
- [x] Data models: `Threat`, `ThreatModel` (pydantic)
- [x] Stage 1 prompt: threat modeling on PR diff
- [x] CLI command: `threatlens pr analyze <PR_URL>` prints Stage 1 output only
- [x] Test against 5 to 10 real PRs, tune prompt (10-PR corpus, 10/10; see eval/)
- **Deliverable:** CLI takes PR URL, prints threat model JSON

## Week 2: Stage 2 (Investigation Skills)
- [x] Skill schema defined (own format, CWE mapped checklist + reachability)
- [x] Write 4 skills: injection, auth, SSRF, deserialization
- [x] Skill registry + lookup logic
- [x] Data models: `InvestigationResult`
- [x] Stage 2 prompt using matched skill checklist
- [x] Wire Stage 1 to Stage 2 end to end
- **Deliverable:** full pipeline, PR in to verdict out

## Week 3: Verdict, Scoring, Polish
- [x] Confidence scoring heuristic (1 to 10 rubric + README table)
- [x] Output formatter (JSON + markdown)
- [x] Error handling: rate limits, provider fallback, empty content retryable
- [x] Cost / token / call logging
- [x] Labeled verdict eval (`eval/verdicts.yaml`)
- [x] README, architecture diagram, rationale in journal + README
- **Deliverable:** polished, demoable v1

## Week 4: Scanner driven discovery + LLM verification
- [x] Semgrep discovery layer
- [x] Execution backend auto detect (local binary or Docker)
- [x] Keep v1 LLM discovery behind `--discovery=llm`
- [x] Generic fallback investigation + `skill_used`
- [x] Registry miss never drops a finding
- [x] Principle based skills rewrite
- [x] Fork aware file fetch
- [x] Re validate labeled eval under Semgrep
- [x] Skill vs generic comparison harness
- **Deliverable (historical):** Semgrep discovery + skill or generic investigation

## v3: CodeQL as a second discovery source
- [x] CodeQL SARIF to Finding
- [x] Fuse Semgrep + CodeQL (`codeql+semgrep`)
- [x] `--discovery=semgrep|codeql|both|llm` + `setup_codeql.py`
- **Deliverable:** fused discovery proven on Juice Shop style PRs

## v3.1: HTML report UI
- [x] Standalone HTML report (inline CSS/JS)
- [x] Finding detail pages and source to sink presentation
- [x] Local hosting: `--serve` and `threatlens report serve`
- **Deliverable:** open locally or serve live

## Default branch repo scan
- [x] Bare repo URL scans default branch (not only PRs)
- [x] Caps for file count and size; tree filters for junk dirs

## Enterprise refactor: evidence driven triage (current product)
- [x] Replace skill routing with one `evidence_investigator_v1`
- [x] Structured evidence schema; code derives verdict
- [x] Separate merge policy (`pass` / `warn` / `require_review` / `block`)
- [x] Optional non authoritative CWE hints only
- [x] Investigate all findings in scope (no small investigate cap for demos)
- [x] Groq first free LLM priority, then OpenRouter capacity
- [x] Rate limit resilience: backoff, chain rotate, inter finding delay, cooldown retry
- [x] CLI rename: top level `threatlens analyze` (`pr analyze` hidden alias)
- [x] UTF-8 console setup without requiring `PYTHONUTF8=1`
- [x] Safer `--serve`: fail on busy port by default, auto save report snapshot, run id banner, no store cache headers
- [x] Security interview: Yes / No / Unknown only
- [x] AI plans questions, follow ups, and a decision brief
- [x] Production assumption fixed; never ask demo / lab / CTF framing questions
- [x] Saved context store + `context show|clear` + `--refresh-context` / `--non-interactive`
- [x] Run logs: `runs list|show`
- [x] Docs: README interview explanation, design, PRD, journal updated for this shape
- **Deliverable:** evidence driven triage with production interview, demo safe serve, Groq first free chain

## Still optional / deferred
- [ ] Multi repo / org wide search support
- [ ] Extra Semgrep rulesets or richer discovery packs
- [ ] Paid model presets for heavy demos (config only)

## Milestones / checkpoints
- End of Week 1: Stage 1 alone produces sensible threats on real PRs
- End of Week 2: Full pipeline runs without manual intervention
- End of Week 3: Demo ready v1
- Current: Evidence driven path + interview + serve safeguards are the story to demo
- Before any interview: review `journal.md` and the README Interview explanation so every layer is explainable unprompted
