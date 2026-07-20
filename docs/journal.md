# Build Journal: ThreatLens

Log every session here. Purpose: capture decisions, failures, and reasoning as they happen, so you can speak to every layer of the project unprompted (interview prep), and so future sessions have real context instead of re-deriving it.

Format per entry:
```
## YYYY-MM-DD — Session N
**Worked on:**
**Decisions made:**
**What broke / didn't work:**
**Why (root cause, not just the fix):**
**Next session:**
```

---

## 2026-07-19 — Session 0 (Planning)
**Worked on:** Defined project scope, named it ThreatLens. Decided to rebuild hackathon project solo for understanding rather than reuse group code. Compared against alternative project (vuln prioritization engine) — decided prioritization engine has more direct interview relevance to Labelbox/Aaron Bacchi's stated problem (backlog validation), while ThreatLens is being built as a personal-understanding project / secondary talking point.

**Decisions made:**
- Two-stage pipeline: threat modeling -> investigation
- Own skill schema, own output schema, own confidence heuristic (not reused from any reference project)
- Provider abstraction: OpenRouter (free-model fallback list) primary, Groq secondary, zero cost, no credits added
- No IaC/cloud infra needed for testing — public vulnerable sample apps instead
- Explicit guardrail: do not present this to interviewers as identical to any existing public tool; frame as "hackathon project, rebuilt solo to go deeper"

**What broke / didn't work:** N/A (planning stage)

**Next session:** Start Week 1 — repo scaffold, GitHub client, provider abstraction

---

## 2026-07-19 — Session 1 (Week 1 foundation)
**Worked on:** Scaffolded the Python package end-to-end for Week 1 deliverable: CLI takes a PR URL and prints Stage 1 threat model JSON.

**Decisions made:**
- `src/` layout with hatchling + typer/rich CLI
- Provider chain built from `providers.yaml`; missing API keys skip that provider rather than hard-failing the whole chain at construct time (fail only if zero providers usable)
- Stage 1 prompt asks for concrete, diff-specific threats and limits investigate=true to cases worth reachability analysis
- `--stage1-only` is default until Week 2 wires investigation; `--full` reserved
- Planning docs copied into `docs/` as source of truth; journal continues here

**What broke / didn't work:** N/A at scaffold time — unit tests cover GitHub parsing, JSON extraction, fallback advance on 429, and prompt assembly. Live PR tuning still pending (needs API keys + real PRs).

**Why (root cause, not just the fix):** N/A

**Next session:** Tune Stage 1 against 5–10 real PRs; start Week 2 skill schema + registry if threat ID quality looks solid

---

## 2026-07-19 — Session 2 (Stage 1 live-tune — blocked on LLM keys)
**Worked on:** Built a 10-PR tuning corpus + eval harness; pre-tuned Stage 1 system prompt from manual diff review before live LLM runs.

**Decisions made:**
- Corpus mix: INTRODUCES (Juice Shop SSTI/SSRF #655, WebGoat JWT), REMEDIATES (dokku cmdi, grafana cmdi, SQLi fix, SSRF bypass, path traversal), NOISE (multer bump, Flask docs)
- Prompt now forces change-intent classification first (INTRODUCES_OR_WORSENS / REMEDIATES / NOISE) so remediations and dep bumps don't get escalate-happy investigate=true
- Require concrete file/symbol citations; soft-cap high-signal threats
- Eval scorer in `scripts/run_stage1_eval.py` checks investigate bounds + expected CWEs
- GitHub auth wired from `gh auth token` into `.env`; still need OpenRouter and/or Groq free-tier keys

**What broke / didn't work:** Cannot execute live Stage 1 yet — `OPENROUTER_API_KEY` and `GROQ_API_KEY` empty.

**Why (root cause, not just the fix):** Free-tier LLM calls require user-owned API keys; none present in env or local config files.

**Next session:** User adds keys to `.env` → run `python scripts/run_stage1_eval.py` → iterate prompt on FAIL cases

---

## 2026-07-19 — Session 3 (Stage 1 live-tune — 10/10)
**Worked on:** Ran the live Stage 1 eval against all 10 corpus PRs with real LLM calls. Final result: 10/10 passed.

**Decisions made:**
- Replaced the entire free-model list in `providers.yaml` — the design-doc models (llama-3.3-70b:free, qwen-2.5-72b:free, deepseek-chat:free, gemini-2.0-flash-exp:free) all now 404 as "paid only" on OpenRouter. New chain: nemotron-3-super-120b-a12b:free → gpt-oss-20b:free → gemma-4-31b-it:free → hy3:free, then Groq. Confirmed provider abstraction earned its keep: config change only, zero code changes.
- Kept the intent-first prompt (INTRODUCES/REMEDIATES/NOISE) — it worked: remediation PRs got investigate=false, noise PRs got zero threats, Juice Shop #655 got both SSTI (CWE-94) and SSRF (CWE-918) flagged for investigation.

**What broke / didn't work:**
1. First run: 3 ERR cases — all four original OpenRouter free slugs 404'd and Groq hit 429 simultaneously. Root cause: OpenRouter rotated its free tier since the design doc was written; model availability is time-sensitive, hence config-driven list.
2. `.env` had a UTF-8 BOM (PowerShell 5 `Set-Content -Encoding utf8`) — harmless here, but rewrote as ASCII.
3. Rich console crashed printing `→` on Windows cp1252 terminal — replaced with `->` and set PYTHONIOENCODING=utf-8 for eval runs.

**Why (root cause, not just the fix):** Free-tier model catalogs churn; any hardcoded model list rots. The fallback chain + config file is the durable mechanism, the specific slugs are disposable.

**Interesting finding:** On WebGoat #2422 (a functionality bugfix), Stage 1 flagged that the new DNS-resolution-based Host header check performs a DNS lookup on user-controlled input — a plausible SSRF-adjacent concern the PR author likely never considered. Good sign for signal quality.

**Next session:** Week 2 — skill schema, 4 CWE skills, registry lookup, Stage 2 investigation prompt, wire full pipeline.

---

## 2026-07-19 — Session 4 (Week 2 — full pipeline)
**Worked on:** Built Stage 2 end-to-end: 4 CWE skills, deterministic registry lookup, investigation prompt, pipeline orchestration, CLI now runs both stages by default.

**Decisions made:**
- Skill files are YAML in top-level `skills/` (injection, auth, ssrf, deserialization), each with `cwe_ids`, `reachability` definition, and a source→sink `checklist`. Extended `Skill` model with a `reachability` field. Injection skill also owns CWE-94/1336 so SSTI routes there.
- Routing stays deterministic (dict CWE→skill), no LLM — matches design.md. Registry indexes every CWE a skill declares.
- Stage 2 only runs on threats with investigate=true; unflagged threats and remediation/noise PRs never hit the second LLM call (cost control + correctness).
- Stage 2 context = PR diff + full head-ref contents of changed files (capped 12k/file, 60k total) fetched via existing GitHub client. Gave the model enough to trace source→sink across files.
- Confidence heuristic embedded in the prompt (9-10 full trace visible, down to 1-2 speculation); when context is insufficient, instructed to lean FALSE_POSITIVE + lower confidence rather than guess TP.
- CLI default flipped to `--full`; `--stage1-only` still available.

**What broke / didn't work:** One skill checklist line ("Check whether the vulnerable path is actually exposed: ...") had an unquoted colon-space, so YAML parsed it as a dict and pydantic rejected it. Root cause: YAML treats `: ` as a mapping delimiter inside block sequences.

Initially fixed by quoting, but that leaves a latent footgun for every future skill author. Follow-up (same session): made the loader tolerant instead — `_normalize_checklist_item` in registry.py coerces a dict-parsed line (`{'SQL': 'is it parameterized?'}`) back to `"SQL: is it parameterized?"`, so unquoted colons in checklist prose just work. Added regression tests (`test_normalize_checklist_item_handles_unquoted_colon`, `test_registry_loads_skill_with_unquoted_colon`). Lesson kept for the record, but the sharp edge is gone.

**Live results (real PRs, nemotron-3-super-120b:free):**
- Juice Shop #655 (intentional bugs): T1 SSTI → TRUE_POSITIVE 9/10 with a 6-step trace (req.body.username → stored → userProfile.js eval(code) sink); T2 SSRF → TRUE_POSITIVE 10/10 (req.body.imageUrl → request.get with only a flag-setting string match, no host validation). Both traces cite real files/functions.
- SQLi-fix PR (#2): Stage 1 marked the (fixed) SQLi investigate=false → pipeline correctly ran zero Stage 2 calls. No false escalation on a remediation.

**Tests:** 20/20 passing (added registry + pipeline + prompt tests, with a ScriptedProvider stub so Stage 2 is covered without live calls).

**Next session:** Week 3 — finalize confidence scoring, markdown report formatter, token/call logging, expand labeled test set, README + architecture diagram.

---

## 2026-07-19 — Session 5 (Week 3 — polish, scoring, verdict eval)
**Worked on:** Token/call usage tracking, markdown report formatter, verdict-accuracy eval harness with a labeled ground-truth set, provider robustness, README architecture + confidence docs.

**Decisions made:**
- Usage tracking (`usage.py`): providers expose `last_usage()` from the API's `usage` block; the fallback chain records into a `UsageTracker`; pipeline attaches a `UsageSummary` (calls, tokens, by-model) to the report. CLI prints it.
- Markdown formatter (`report.py`) + CLI `--format md|json`. Produces an interview-ready report: summary, Stage 1 table, per-threat Stage 2 verdict with full reasoning chain.
- Verdict eval (`eval/verdicts.yaml` + `scripts/run_verdict_eval.py`): labels each PR with expected TRUE_POSITIVE bounds + expected TP CWEs, runs the FULL pipeline, scores. Distinct from the Stage 1 eval — this measures end-to-end TP/FP discrimination, the actual product promise.
- Confidence heuristic finalized as a 1-10 rubric in the Stage 2 prompt and documented in README.

**What broke / didn't work (all real, all fixed):**
1. js655 Stage 1 first run: free model returned truncated JSON (`"threats":` then nothing) — hit an output cap. Added `max_tokens: 4096` to both providers.
2. js655 Stage 2 then crashed with `AttributeError: 'NoneType' has no attribute 'strip'` — the model returned `content: null` (finish_reason=length) on the huge investigation prompt. Root cause: the investigation context bundled full contents of all 18 changed files (~100k chars), overflowing a free model. Fix (two parts): (a) treat empty/null content as a *retryable* LLMError so the chain advances instead of crashing; (b) trim context — only fetch real source files (code suffixes, skip assets/lockfiles/yml), caps lowered to 8k/file and 32k total. After the trim, js655 investigated both threats cleanly (SSTI + SSRF, both TRUE_POSITIVE 9-10) in ~30k tokens.
3. First verdict-eval run: 3/5. ssrf167 (an SSRF *remediation*) got flagged and called TRUE_POSITIVE conf=7 — a false escalation. On the clean re-run after the context/robustness fixes it came back 0 TP and passed. Non-determinism at temp 0.2 on a genuinely borderline PR (the PR both adds a denylist AND leaves outbound requests in place). Noted as the weakest case in the set; worth watching if the corpus grows.

**Why (root cause):** Free-tier models have real output-length and context limits. Feeding entire changed files was over-eager; source-only + tighter caps preserves the source→sink signal while staying within budget. Empty completions must be retryable, not fatal.

**Final state:** unit tests 26/26; Stage 1 eval 10/10; verdict eval 5/5 (js655 2xTP with correct CWEs, all four remediation/noise PRs 0 TP). Full pipeline is demoable: `threatlens pr analyze <URL> --format md -o report.md`.

**Next session:** Week 4 (optional) — more skills, multi-repo, provider fallback stress test; otherwise the v1 is interview-ready.

---

## 2026-07-20 — Session 6 (Week 4 — v1 -> v2 architecture pivot)
**Worked on:** Replaced LLM-based discovery with Semgrep; kept the LLM as the
verification (false-positive-elimination) layer; rewrote the 4 skills to be
principle-based; added a generic fallback so nothing is dropped; re-ran the eval
and a skill-vs-generic comparison.

**Why the pivot (the honest motivation):**
- *LLM-only discovery has coverage gaps.* v1 only investigated classes the model
  thought to raise. On js655 the LLM raised the 2 planted bugs (SSTI + SSRF);
  Semgrep raised those **plus** real JWT-exposure, hardcoded-secret, CSRF and
  directory-listing issues in the same diff. A static analyzer with a large rule
  corpus is simply broader at discovery than a single LLM prompt.
- *Corpus-specific skills don't generalize.* v1 skill checklists referenced
  concrete Juice Shop/WebGoat APIs. Rewrote each skill around the underlying
  security principle (data/code separation, verified identity, validated
  destination, safe deserialization) with API names demoted to illustrative
  `mitigation_examples_by_ecosystem` hints. The LLM is told the specific
  API/library is irrelevant — judge whether the security property holds.

**Architecture now:** PR -> Semgrep discovery (`--config=p/default`, free, no key)
-> `Finding[]` -> deterministic CWE→skill lookup (or generic fallback) -> LLM
investigation per finding -> verdict. `--discovery=llm` keeps the v1 path for
comparison. New `skill_used` field records "skill name" or "generic" so no
finding is ever silently uninvestigated (asserted by `test_no_finding_dropped_on_registry_miss`).

**What broke / didn't work (all real, all fixed):**
1. `--config=auto` refused to run: "Cannot create auto config when metrics are off."
   Switched default to `p/default` (free community ruleset, no telemetry, no key).
   `p/default` also caught more than `p/security-audit` on js655 (13 vs 1).
2. **Semgrep found 0 files to scan.** Root cause: js655 is a *fork* PR, so its head
   branch/ref doesn't exist in the base repo — every `contents?ref=<head_ref>` 404'd.
   (v1 never noticed because `gather_file_context` swallowed the errors and fell
   back to diff-only; Semgrep needs real files.) Fix: capture head-repo owner/name
   + head SHA in `fetch_pr`, add `fetch_pr_file` that tries head-repo@SHA, then
   head-repo@ref, then base@ref. After that, 15 files materialized and Semgrep
   surfaced the eval/SSRF sinks.
3. Windows has no native `semgrep` binary (pip package is Linux/macOS/WSL only).
   Discovery auto-detects a backend: local `semgrep` if on PATH, else the official
   `semgrep/semgrep` Docker image. Ran via Docker here.

**Eval — labeled set under Semgrep discovery (`scripts/run_verdict_eval.py`): 5/5.**
- js655: 6 TRUE_POSITIVEs including the planted SSTI (CWE-95, eval) and SSRF
  (CWE-918), plus real CSRF/JWT/dir-listing issues; 2 hardcoded-secret findings
  ruled FALSE_POSITIVE by the LLM. (A few findings errored out under free-tier
  rate limits — surfaced in `report.errors`, never silently dropped.)
- sql2 / ssrf167 / path510 / multer704: Semgrep finds **0** on the fixed/benign
  HEAD -> 0 investigations -> 0 false alarms. Scanning HEAD gives remediation PRs
  a clean, automatic pass with zero LLM cost.

**Skill-vs-generic comparison (`scripts/run_skill_vs_generic.py`):** scan each PR
once, investigate the same findings twice (matched skills vs `--force-generic`),
compare. Result on js655 (the only PR with findings; capped to top 8 by severity):
- **Skill-matched findings (3):** CWE-95 eval ×2 (Injection skill) + CWE-918 SSRF
  (SSRF skill). **Skill and generic reached the identical verdict on all three —
  TRUE_POSITIVE.** On this set the principle-based *generic* lens was already
  sufficient to catch the same true positives; skills added no accuracy delta.
- **Registry-miss findings (5):** CWE-798/522 (hardcoded/insufficiently-protected
  credentials). These have no skill, so both modes used the generic lens by
  definition — any difference there is model nondeterminism, not a skills effect.
  Two of them flipped between the two generic runs, and two errored under free-tier
  rate limits (surfaced, not dropped).
- **Honest read:** because I intentionally gave the generic fallback the *same*
  source→sink→mitigation reasoning the skills use, the two converge on clear-cut
  cases — which is the desired behavior (no finding is worse off without a skill).
  Detecting a measurable skill advantage would need a larger corpus of subtler,
  borderline cases; the initial script that reported "skills change 4/8" was
  double-counting rate-limit ERRORs and generic-vs-generic noise, so I corrected
  it to compare only skill-matched, non-errored findings.

**Deferred:** CodeQL as a second, dataflow-grade discovery source (needs a
build/DB step; documented in design.md as a future extension).

**State:** all unit tests green (added Semgrep-parse, generic-fallback, and
no-drop tests). Default `threatlens pr analyze <URL>` now runs Semgrep discovery.

---

## 2026-07-20 — Session 7 (v3 — CodeQL as a second discovery source)
**Worked on:** Added CodeQL (dataflow/taint) alongside Semgrep, with a fusion
mode that de-duplicates overlapping findings. `--discovery` now takes
`semgrep` (default) | `codeql` | `both` | `llm`.

**Design:**
- `discovery/codeql_scan.py`: materialize the PR's changed files (reusing the
  Semgrep materializer), `codeql database create` on the temp dir, then
  `codeql database analyze <db> <lang>-security-extended.qls --format=sarif-latest`.
  Parse SARIF -> `Finding`; CWE ids come from each rule's `external/cwe/cwe-NNN`
  tags (resolved by `ruleId`, falling back to `result.rule.index`).
- No-clone / no-build: only extraction-only languages (Python, JS/TS, Ruby) are
  analyzed — we can't run an arbitrary repo's compiler, so compiled langs are
  skipped by design.
- `discovery/fuse.py`: de-dup on `(file basename, line, CWE set)`; a shared
  finding is investigated once and its `source` becomes `codeql+semgrep` (both
  tools agreeing = stronger signal). Added a `source` field to `Finding`.
- Runtime: CodeQL is a ~670 MB self-contained bundle (CLI + prebuilt query packs),
  not pip-installable. `scripts/setup_codeql.py` downloads/extracts it into
  `.codeql/` (git-ignored); runner also accepts `codeql` on PATH or
  `THREATLENS_CODEQL`.

**What broke / didn't work (all real, all fixed):**
1. No CodeQL anywhere — not on PATH, no usable Docker image (ghcr bundle image is
   auth-gated). Solution: pull the official release bundle (CLI + packs) via
   `gh release download` and run the native binary. Bundle is self-contained, so
   analysis needs no network.
2. **First live scan crashed on cleanup** with `WinError 145: directory not empty`
   on `db_javascript\...\cached-strings\tuple-pool`. CodeQL leaves locked cache
   files in the DB dir, so `TemporaryDirectory.__exit__` failed *after* the
   analysis succeeded — the findings were computed then thrown away. Fix: manage
   the temp dir manually (`mkdtemp` + `finally: rmtree(ignore_errors=True)`).

**Live result (js655, javascript-security-extended): 10 findings, ~75s.**
CodeQL confirmed the planted **SSRF (CWE-918, `js/request-forgery`)** at
`profileImageUrlUpload.js` via real dataflow — the same sink Semgrep flags. It
also surfaced dataflow-grade issues Semgrep *missed*: ReDoS taint (CWE-1333),
`http-to-file-access` (CWE-434), insecure randomness (CWE-338), weak password
hashing (CWE-916), missing rate limiting (CWE-770). Conversely, Semgrep caught
the `eval` SSTI (CWE-95) that CodeQL's JS suite didn't flag here — concrete
evidence the two sources are complementary, which is the whole point of
`--discovery=both`. (Caveat: the shared SSRF is reported at line 15 by CodeQL vs
16 by Semgrep, so exact-line fusion investigates it twice rather than merging —
acceptable under the no-drop principle; over-merging would be worse.)

**Semgrep vs CodeQL (why keep both):** Semgrep is fast/pattern-based and broad on
config-y issues (hardcoded secrets, JWT/CSRF audit rules); CodeQL is slower but
does real taint tracking, so it is higher-fidelity on source→sink classes
(injection, SSRF). `--discovery=both` fuses them so a sink flagged by both is
investigated once with `source=codeql+semgrep`. CodeQL remains the "confirm
reachability at discovery time" upgrade the design flagged in v2.

**State:** unit tests green (added SARIF-parse, CWE-tag, and fusion/dedup tests).

---

## 2026-07-20 — Session 8 (Report UI — HTML renderer)
**Worked on:** A self-contained HTML report view wired to the real
`PipelineReport` schema, plus `--format html` on the CLI and a re-render script.

**Decisions made:**
- **Server-side rendered, single file.** `render_html(report)` in `report.py`
  produces one standalone `.html` with inline CSS/JS — no framework, no build, no
  external assets. Opens locally or serves from any static server. Wired as
  `threatlens pr analyze <URL> --format html -o report.html`; `scripts/render_report.py`
  re-renders any saved report JSON without re-running discovery/LLM.
- **Built against real data, not mocks.** Rendered the actual v1 `e2e_js655.json`
  dump first to shake out bugs, then generated a fresh `--discovery=both` report
  on js655 to exercise every state (TP/FP, skill vs generic, semgrep/codeql/both).
- **Design register:** flat (no shadows/gradients), dense, mono for code/loci,
  muted palette. TRUE_POSITIVE = restrained red left-border; FALSE_POSITIVE =
  muted green; `skill_used` shown as a tag (specific skill vs dimmed italic
  "generic"); `source` as a tag where `codeql+semgrep` is filled/emphasized as
  higher-confidence. Summary strip = finding/TP/FP/error counts + LLM calls/tokens.
- **Signature interaction:** each finding is a native `<details>` (accessible,
  works without JS). On open, the reasoning steps reveal with a short staggered
  fade/slide (`animation-delay: calc(var(--i)*70ms)`), and a vertical connector
  line + node dots draw the source→sink→verdict trace — reinforcing what Stage 2
  does. Fully disabled under `prefers-reduced-motion`. Only JS is a tiny
  expand/collapse-all toggle.
- Uses only the existing schema fields (`threat_model`, `findings`, `source`,
  `skill_used`, `verdict`, `confidence`, `reasoning_chain`, `usage`) — invented
  nothing. Per-finding token cost isn't in the schema (usage is aggregate), so the
  UI shows aggregate usage rather than fabricating per-finding numbers.

**Small fusion improvement (enabled the UI's "confirmed by both" state with real
data):** CodeQL and Semgrep report the same js655 SSRF one line apart (15 vs 16),
so the old exact-line fusion never marked anything `codeql+semgrep`. Changed
`fuse.py` to de-dup on `(file, CWE set)` within a `LINE_WINDOW` (±3 lines) — real
tools disagree slightly on line numbers. Added line-window merge tests.

**What broke / didn't work:**
- Shell/`Get-Location` briefly returned empty output after the workspace root
  changed to "none" mid-session; re-anchoring with `Set-Location` to the project
  path restored it. No code impact.

**Live sample (js655, `--discovery=both`, capped to 8 findings):** fused 23 raw ->
19 (4 line-window merges) -> top 8 investigated: **4 TRUE_POSITIVE / 4 FALSE_POSITIVE**,
0 errors, 8 LLM calls. The render exercises every state: the SSRF (CWE-918) shows
`codeql+semgrep` (both tools, higher-confidence) with the SSRF skill and a
TRUE_POSITIVE trace; the eval/template-injection findings (CWE-95/1336) use the
Injection skill; the credential/JWT findings (CWE-798/522/345) fall to the generic
lens and come back FALSE_POSITIVE. Output at `eval/runs/js655_both_report.html`
(git-ignored run dir; regenerate with `--format html`).

**State:** unit tests green (added line-window fusion tests); `--format html`
produces an interview-demoable report.

**Follow-up — serve instead of writing files:** added `src/threatlens/serve.py`
(a tiny in-memory `ThreadingHTTPServer` that holds the rendered HTML as bytes and
serves it on `/` until Ctrl+C; auto-increments past a busy port). Wired
`--serve [--port --no-browser]` onto `pr analyze` and a `threatlens report serve
<report.json>` command to host a saved dump with no file written. Verified: binds,
serves the full report (200), 404s unknown paths. 46 tests green.

**README pass:** rebuilt the architecture diagram as a layered flowchart
(ingest → discovery → routing → investigation → output), added a runtime
**workflow** sequence diagram, and wrote an **Interview explanation** section
(thesis: tools enumerate cheaply/deterministically, the LLM only verifies
reachability on each finding; plus defensible design decisions, validation,
honest limitations, and a 60-second pitch). Kept Mermaid edge syntax to the
pipe-label form that already renders in this repo.

---

## 2026-07-20 — Session 9 (Report UI visual redesign)
**Worked on:** Hierarchy/spacing redesign of the HTML report so it stops reading
as a wall of equal-weight monospace.

**What changed and why:**
- **Typefaces split by role.** Space Grotesk (display) for title / labels / stat
  numbers / human finding titles; Inter for body/meta; monospace *only* for
  rule ids, paths, and CWEs. That was the main fix for the flat look.
- **Verdict first.** Filled pills ("True positive" / "False positive") instead of
  plain colored text; dropped the thin left-edge bars that were easy to miss.
- **Human label over rule id.** Row primary text is the skill name (or readable
  threat name); the raw scanner rule id is muted secondary text, with the full
  id repeated in the expanded detail.
- **Confidence as a bar**, not equal-weight text next to the verdict.
- **Source priority.** Dual-confirmed findings show a filled "both confirmed"
  badge; single-source stays an outlined quiet tag.
- **Spacing.** Gapped rounded rows; security stats vs usage stats in separate
  groups (usage gets a muted tint so tokens don't compete with TP/FP counts).
- Motion kept subtle (~180ms step reveal; `prefers-reduced-motion` respected).

**State:** HTML unit tests updated for the new markup; sample report re-rendered.

**Follow-up — Snyk-style report layout:** rebuilt the HTML template after a
scanner-dashboard reference (summary totals + colored severity-style cards +
columnar finding table). Adapted to ThreatLens vocabulary (TP/FP/both-confirmed
instead of Critical/High/Medium/Low). No sidebar/app chrome — still a single
static report. Verdict letter badges (TP/FP), blue finding names, CWE/location/
source/lens/conf columns, expand-for-trace. Tests updated.

**Follow-up — per-finding detail pages:** clicking a finding now opens a separate
page (`/finding/<id>`) with the full vulnerability write-up sections:
identification (incl. severity mapped from scanner), location, description,
evidence/reasoning trace, impact, verdict/confidence, remediation (from matched
skill mitigation patterns for now — LLM-authored fix text deferred), and
metadata. Multi-page serve + `write_html_report` directory output. Schema fields
for LLM remediation/severity left for a later Stage 3.

---

## 2026-07-20 — Default-branch repo scan
**Worked on:** Bare repo URL no longer auto-picks the latest open PR (which
could be a deps-only bump with 0 findings). Instead: bare repo → default-branch
code scan; PR URL or `--pr N` → PR-scoped changed-files scan.

**Decisions made:**
- Synthetic `PullRequest` with `scope="repo"` so Semgrep/CodeQL materialize paths reuse existing fetch
- Caps: 200 files, 200KB/file, top 15 investigations by severity (cost control)
- Tree via GitHub Trees API + suffix/dir filters (skip `node_modules`, etc.)

**What broke / didn't work:** Auto-latest-PR on damn-vulnerable-MCP-server
landed on a Snyk starlette bump (`requirements.txt` only) → empty report looked
like a product failure.

**Why:** Convenience shortcut optimized for "pick something to scan" but wrong
for vulnerable demo repos where the interesting code is on `main`, not the
latest PR.

**Next session:** Optional live smoke on damn-vulnerable-MCP-server without `--pr`.

---

## 2026-07-20 — Windows Semgrep / Docker UX notes
**Worked on:** Clarified for myself (and future demos) how Semgrep shows up in
Docker Desktop on Windows — after confusing “no Semgrep image” while looking at
the wrong tab.

**Decisions / facts:**
- Default + `--discovery both` on Windows need **Docker Desktop running**.
- Semgrep uses `docker run --rm … semgrep/semgrep` — one-shot container, then gone.
- Look under Docker Desktop → **Images** (search `semgrep`), **not Containers**.
  A lasting Semgrep container will not appear; that is expected.
- `--discovery codeql` alone does **not** need Docker (local `.codeql/` bundle).
- macOS/Linux can use a local `pip install semgrep` binary and skip Docker.

**What broke / didn't work:** Looking at Containers (other long-running apps
visible) and assuming Semgrep was missing. Image was already pulled
(`semgrep/semgrep:latest`); CLI `docker images semgrep/semgrep` confirmed it.

**Why:** Mental model was “I should see a running Semgrep container.” ThreatLens
never leaves one running — only the image must exist, and the engine must be up.

**Next session:** Keep this out of README unless we add a dedicated Windows FAQ;
journal is the right place for demo gotchas.
