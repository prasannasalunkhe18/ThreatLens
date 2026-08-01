# Design: ThreatLens PR Vulnerability Triage Agent

## Architecture overview (evidence driven)

Static analysis discovers candidates. A short Yes / No / Unknown interview
gathers production context. One evidence investigator LLM call per finding
returns structured evidence. Code derives the technical verdict and a separate
merge policy action.

```
PR or repo URL
  -> GitHub Client (PR changed files, or default-branch tree; fork aware)
  -> Discovery (materialize source to a temp dir), one of:
       - semgrep (default): pattern rules
       - codeql: dataflow / taint via security-extended suites
       - both: Semgrep + CodeQL, fuse and de-dup
       - llm (legacy): v1 Stage 1 threat modeling
       -> Finding[]
  -> Context interview (interactive runs)
       - AI plans Yes / No / Unknown questions from findings
       - Developer answers (saved per repository)
       - Optional AI follow ups
       - AI decision brief for the investigator
  -> Investigation: evidence_investigator_v1 per finding
       -> Structured evidence (status: present / absent / unknown)
       -> Deterministic verdict + separate merge policy
  -> Report (JSON / Markdown / HTML) and optional --serve
```

Every discovered finding in scope is investigated. There is no CWE to skill
router in the active path. Optional CWE hints may supplement the prompt; they
never pick a different investigator or decide the verdict.

Semgrep and CodeQL scan the PR HEAD (or default branch for repo scans). A PR
that fixes an issue simply surfaces no finding. That avoids false alarms on
remediations.

### Why tools for discovery and LLM for verification
- LLM only discovery has coverage gaps. The model only checks classes it thinks
  to check. A large Semgrep or CodeQL corpus surfaces classes the LLM would skip.
- LLMs are strong at reading a concrete path and answering "can attacker input
  reach this sink without an adequate control?" They are weaker at open ended
  hunting.
- Corpus specific skill checklists did not generalize well. The evidence schema
  asks for the same structured facts on every finding instead.

### CodeQL as a second discovery source
CodeQL adds true dataflow and taint tracking. Semgrep matches patterns; CodeQL
runs `*-security-extended` query suites over a built database.
Module: `discovery/codeql_scan.py`.

- No clone, no build: changed files (or a capped default-branch set) are
  materialized to a temp dir. Only extraction only languages are analyzed
  (Python, JavaScript/TypeScript, Ruby). Compiled languages are skipped by design.
- SARIF to Finding: CWE ids come from rule tags.
- Fusion (`--discovery=both`): de-dup on file, line window, and CWE set. Shared
  findings get `source=codeql+semgrep`.
- Runtime: `scripts/setup_codeql.py` installs the bundle under `.codeql/`, or set
  `THREATLENS_CODEQL`.

### Platform note (scanner execution)
Semgrep has no native Windows binary. Discovery auto detects a local `semgrep`
on PATH (Linux / macOS / WSL), otherwise the official Docker image. Use
`--config=p/default` (community rules, no telemetry). CodeQL runs from the
extracted bundle on all platforms.

Docker on Windows runs one shot containers. Expect the image under Docker Desktop
Images, not a long lived Semgrep container.

## Components

### 1. GitHub Client
- GitHub REST API with a read only PAT
- PR mode: diff, changed files, head repo and SHA (fork aware)
- Repo mode: default branch tree, scannable sources, size caps
- No LLM involved

### 2. Discovery (`--discovery=semgrep|codeql|both|llm`)
- Semgrep (default): materialize sources, run Semgrep, parse into `Finding`
- CodeQL: build DB, run security-extended suites, parse SARIF
- Both: fuse via `discovery/fuse.py`
- LLM (legacy): v1 threat model for comparison and eval

### 3. Context interview (`context/`)
- Catalog of production only Yes / No / Unknown questions
  (reachability, auth, sensitive data, production enablement, edge controls,
  CWE family follow ups, merge block preference)
- AI planner (`context/interview.py`) chooses and may rewrite questions
- AI follow ups after answers
- AI decision brief (`context/decide.py`) for investigation guidance
- Persist answers per repository (`context/store.py`)
- Never asks whether the target is a demo, CTF, or lab app
- `--non-interactive` skips prompts; `--refresh-context` re asks

### 4. Evidence investigation
- One investigator: `evidence_investigator_v1` (`prompts/` + `stages/investigate.py`)
- Input: finding, code context, saved answers, decision brief, optional hints
- Output: structured evidence items with status present / absent / unknown
- `verdict.py` derives `confirmed` / `likely` / `not_exploitable` /
  `insufficient_context` / `suppressed`
- `policy.py` derives separate merge action:
  `pass` / `warn` / `require_review` / `block`
- Missing evidence stays unknown. Unknown is never treated as proof of safety.

### 5. Provider abstraction
- Interface: `llm_call(prompt, schema) -> parsed_response`
- Config driven chain in `providers.yaml` (swap models without code changes)
- Default free tier order:
  1. Groq `llama-3.3-70b-versatile` (preferred quality)
  2. OpenRouter free models (capacity when Groq rate limits)
- Retries with backoff on 429, rotate through the chain, delay between findings
  (`THREATLENS_LLM_DELAY`, default 2s), one cooldown retry for failed findings
- `--model <id>` means try first, then continue the full chain

### 6. CLI
- Primary: `threatlens analyze <PR_or_repo_URL>`
- Hidden alias: `threatlens pr analyze` (compat)
- Also: `report serve`, `context show|clear`, `runs list|show`
- Important flags: `--serve`, `--non-interactive`, `--refresh-context`,
  `--allow-port-fallback`, `--discovery`, `--stage1-only`, `--model`, `--pr`

### 7. Report hosting
- `--serve` hosts HTML via `serve.py`
- Busy port fails by default (avoids serving a stale report silently)
- Auto saves a report snapshot under the user runs directory when serving
- HTML shows a run id; responses use `Cache-Control: no-store`

## Data models (conceptual)

Findings carry discovery metadata (`source`, CWE ids, file, line, severity).
Investigations carry structured evidence, a derived verdict, confidence 1 to 10,
reasoning, usage, and a separate policy action. Reports aggregate findings,
errors, and token usage for JSON, Markdown, and HTML.

Legacy v1 types (`Threat`, `ThreatModel`, TRUE_POSITIVE / FALSE_POSITIVE) remain
for LLM discovery and historical evals.

## Provider config shape
```yaml
providers:
  - name: groq
    models:
      - llama-3.3-70b-versatile
  - name: openrouter
    models:
      - nvidia/nemotron-3-super-120b-a12b:free
      - google/gemma-4-31b-it:free
      - openai/gpt-oss-20b:free
      - tencent/hy3:free
default_provider: groq
```

## Key design decisions
- Evidence schema and confidence heuristic are original to this project
- LLM returns evidence; code owns verdict and merge policy
- No finding dropped because a skill was missing (skills are not on the active path)
- Production assumption is fixed; interview never frames the app as a lab
- Free tier priority favors smarter Groq first, then OpenRouter capacity
- Safe local serve behavior so demos do not show the wrong report

## Testing approach
- Unit tests for models, providers, policy, verdict, context, serve, pipeline
- Labeled PR corpus for discovery and verdict evals (`eval/`)
- Public vulnerable apps for live demos (for example DVNA, Juice Shop)
- Treat every live target as production in questions and write ups
