# Design: ThreatLens — PR Vulnerability Triage Agent

## Architecture Overview (v2 — scanner-driven discovery + LLM verification)

v2 replaces the v1 LLM-based discovery step with **Semgrep** as the discovery
layer, and keeps the LLM as the investigation/verification layer. Discovery is
now deterministic and broad (a static analyzer with hundreds of community
rules), while the LLM does what it is uniquely good at: reading the real code
path and deciding whether a flagged pattern is actually reachable/exploitable —
i.e. eliminating false positives.

```
PR URL
  -> GitHub Client (fetch diff, files, metadata; head-repo/SHA aware for forks)
  -> Discovery (materialize changed source files to a temp dir), one of:
       - semgrep (default): semgrep --config=p/default --json  (pattern rules)
       - codeql: build DB + run *-security-extended.qls        (dataflow/taint)
       - both:   run Semgrep + CodeQL and fuse/de-dup findings
       - llm (legacy): v1 Stage-1 LLM threat modeling
       ->  Finding[]  (finding_id, cwe_ids, file, line, rule_id, severity, source)
  -> Registry lookup (deterministic CWE -> skill; NO LLM)
       -> matched skill, or the generic fallback lens on a miss
  -> Investigation: LLM call per finding
       -> source -> sink trace + reachability reasoning (skill or generic)
       -> verdict + confidence + reasoning_chain + skill_used
  -> Output formatter (JSON / markdown report)
```

Every finding is investigated: a registry miss falls back to the generic lens
(`skill_used="generic"`) rather than being dropped. Semgrep scans the PR's HEAD
state, so a PR that *fixes* an issue surfaces no finding — no false alarm.

### Why the pivot (v1 -> v2)
- **LLM-only discovery has coverage gaps:** the model only checks classes it
  thinks to check. A static analyzer with a large rule corpus surfaces classes
  the LLM would skip (found real JWT/CSRF/hardcoded-secret issues alongside the
  planted SSTI/SSRF on our test PR).
- **Corpus-specific skills don't generalize:** v1 skills referenced concrete
  APIs seen in Juice Shop/WebGoat. v2 skills are rewritten to state the
  underlying security *principle* (data/code separation, verified identity,
  validated destination, safe deserialization), so they apply across languages
  and frameworks. Concrete APIs are demoted to illustrative, non-authoritative
  hints.

### CodeQL — second discovery source (implemented)
CodeQL adds true dataflow/taint tracking alongside Semgrep. Where Semgrep matches
syntactic patterns, CodeQL runs its `*-security-extended` query suites over a
built database, so it confirms source→sink taint rather than pattern presence.
Module: `discovery/codeql_scan.py`.
- **No-clone, no-build:** the PR's changed files are materialized to a temp dir
  and a DB is built there. Only extraction-only ("no-build") languages are
  analyzed — Python, JavaScript/TypeScript, Ruby — since we cannot run an
  arbitrary repo's compiler. Compiled languages are skipped by design.
- **SARIF -> Finding:** results are parsed from SARIF; CWE ids come from each
  rule's `external/cwe/cwe-NNN` tags (resolved by ruleId or rule index).
- **Fusion (`--discovery=both`):** Semgrep + CodeQL findings are de-duplicated on
  `(file basename, line, CWE set)`; a shared finding is investigated once and its
  `source` becomes `codeql+semgrep` (both tools agreeing is a strong signal).
- **Runtime:** CodeQL ships as a large self-contained *bundle* (CLI + prebuilt
  query packs), not a pip package. `scripts/setup_codeql.py` downloads/extracts it
  under `.codeql/` (git-ignored); the runner also accepts a `codeql` on PATH or a
  `THREATLENS_CODEQL` override.

### Platform note (scanner execution)
The `semgrep` pip package does not run natively on Windows; the discovery layer
auto-detects a backend — a local `semgrep` binary if on PATH (Linux/macOS/WSL),
otherwise the official `semgrep/semgrep` Docker image. We use `--config=p/default`
(free community ruleset, no telemetry) rather than `--config=auto`, which refuses
to run unless anonymous metrics are enabled. CodeQL runs from the extracted bundle
(native binary on all platforms).

## Components

### 1. GitHub Client
- Uses GitHub REST API (personal access token, read-only scope)
- Fetches: PR diff, changed file contents, commit metadata
- Plain API wrapper, no LLM involved here

### 2. Discovery (`--discovery=semgrep|codeql|both|llm`)
- **Semgrep (default):** materialize the PR's changed source files to a temp dir,
  run `semgrep --config=p/default --json`, parse into `Finding` models
  (`finding_id, cwe_ids, file, line, rule_id, message, severity, source`).
  Deterministic, free, no API key. Module: `discovery/semgrep_scan.py`.
- **CodeQL:** build a DB from the same materialized files and run the language's
  `*-security-extended.qls` suite (dataflow/taint). Module: `discovery/codeql_scan.py`.
- **Both:** run Semgrep + CodeQL and fuse/de-dup (`discovery/fuse.py`).
- **LLM (legacy, `--discovery=llm`):** v1 behavior — LLM reads the diff and emits a
  CWE-mapped `ThreatModel` with go/no-go per threat. Kept for comparison/eval.

### 3. Skill Registry (principle-based, v2)
- A skill is a YAML file per vulnerability class declaring:
  - `cwe_ids` covered
  - `reachability` — when the class is genuinely reachable
  - `source_definition` / `sink_definition` — stated as security *principles*, not
    API names (e.g. "a value handed to an interpreter as structure rather than data")
  - `mitigation_patterns` — principle-level controls (structural separation,
    verified identity, validated destination, safe parsing)
  - `mitigation_examples_by_ecosystem` — illustrative hints only, NOT the checklist
  - `checklist` — generic source→sink→mitigation→reachability questions
- Skills: injection (89/78/79/77/94/95/1336/943), auth (287/306/862/863/639),
  SSRF (918/611), deserialization (502).
- Matching: `Finding.cwe_ids` -> dict lookup -> matched skill, or the **generic
  fallback lens** on a miss. Deterministic, no LLM. **No finding is ever dropped
  on a registry miss** (enforced by test).

### 4. Investigation (verification layer)
- Input: a finding (or legacy threat) + the matched skill (or generic lens) +
  head-ref code context (fetched from the head repo/SHA, fork-aware).
- Prompt asks the LLM to trace source→sink, judge whether the security property
  holds, and rule the finding TRUE_POSITIVE or FALSE_POSITIVE with confidence.
- Output schema: `InvestigationResult` (adds `skill_used`: skill name or `"generic"`).
- Generic fallback prompt lives at `prompts/investigate_generic.md`.
- This is the "trace it and decide if it's real" false-positive-elimination step.

### 5. Provider Abstraction
- Single interface: `llm_call(prompt, schema) -> parsed_response`
- Config-driven provider selection with fallback chain, all free tier, no paid usage:
  1. OpenRouter free models, tried in order:
     - meta-llama/llama-3.3-70b-instruct:free
     - qwen/qwen-2.5-72b-instruct:free
     - deepseek/deepseek-chat:free
     - google/gemini-2.0-flash-exp:free
  2. Groq (llama-3.3-70b-versatile) as secondary if all OpenRouter free models are rate-limited
- On rate-limit/error response, abstraction automatically tries next provider/model in list
- Swapping provider = config change, not code change

### 6. CLI
- `threatlens pr analyze <PR_URL> [--context-file] [--output] [--model]`
- Prints/saves threat model + investigation results

## Data Models (pydantic)

```python
class Threat(BaseModel):
    threat_id: str
    name: str
    description: str
    cwe_ids: list[str]
    investigate: bool  # go/no-go

class ThreatModel(BaseModel):
    pr_summary: str
    threats: list[Threat]

class InvestigationResult(BaseModel):
    threat_id: str
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE"]
    confidence: int  # 1-10
    reasoning_chain: list[str]

class Skill(BaseModel):
    cwe_ids: list[str]
    name: str
    checklist: list[str]
```

## Provider Config Example
```yaml
providers:
  - name: openrouter
    models:
      - meta-llama/llama-3.3-70b-instruct:free
      - qwen/qwen-2.5-72b-instruct:free
      - deepseek/deepseek-chat:free
      - google/gemini-2.0-flash-exp:free
  - name: groq
    models: [llama-3.3-70b-versatile]
default_provider: openrouter
```

## Key Design Decisions
- Skill format, output schema, and confidence heuristic are original (not reused from any reference project)
- Routing between Stage 1 -> Stage 2 skill is deterministic lookup, not another LLM call (keeps cost/complexity down, LLM only used for actual reasoning steps)
- Provider abstraction chosen specifically to maximize free-tier usage across services rather than depend on one, no paid credits required anywhere

## Testing Approach
- Sample PRs from OWASP Juice Shop / WebGoat / DVWA forks (known vulnerable code, controllable ground truth)
- Manually label expected verdict for each test PR before running, compare against tool output
