# PRD: ThreatLens PR Vulnerability Triage Agent

## Problem
Static analysis tools (Snyk, Semgrep, CodeQL, and others) flag security issues
on every PR, but they lack product context. Noise is high. They do not know
whether a flagged pattern is reachable or exploitable on a real path. Manual
triage does not scale with PR volume.

## Goal
Build ThreatLens: an agent that, given a GitHub PR or repository URL, discovers
candidate issues with static analysis, gathers production context through a short
Yes / No / Unknown interview, investigates each finding with structured LLM
evidence, and produces a technical verdict plus a separate merge recommendation
before the code merges.

## Target use case
Portfolio and interview demo for security engineering roles, especially AI
security engineer interviews. Complementary to backlog remediation workflows
(for example Snyk plus Cursor style fix loops). ThreatLens operates at PR time
(pre merge), not backlog time (post merge).

## Core features (in scope)
1. Fetch a PR or default branch tree via the GitHub API
2. Discovery with Semgrep, CodeQL, or both (legacy LLM discovery still available)
3. Interactive security interview: Yes / No / Unknown only, AI planned questions
   and follow ups, production assumption always on
4. Evidence investigation for every finding (`evidence_investigator_v1`)
5. Deterministic verdicts (`confirmed` / `likely` / `not_exploitable` /
   `insufficient_context` / `suppressed`) and separate merge policy
   (`pass` / `warn` / `require_review` / `block`)
6. Structured reports: JSON, Markdown, HTML, and local `--serve`
7. CLI: `threatlens analyze <URL>` (hidden `pr analyze` alias for compat)
8. Free tier LLM chain: Groq first, OpenRouter free models as fallback

## Out of scope
- No live cloud or IaC environment; public sample apps for demos
- No auto remediation or auto fix loop
- No org wide multi repo search (still deferred)
- No paid LLM requirement; free tier is the default path

## Historical note on skills
Early versions used CWE skill YAML and a registry. The active product path no
longer routes by skill. Optional CWE hints may still supplement prompts. Skill
YAML under `skills/` is historical.

## Success criteria
- Runs end to end on a real public PR or repo and produces a sensible report
- Distinguishes real issues from noise using evidence, not vibes
- Interview questions stay production oriented (never "is this a demo?")
- Every design decision is explainable unprompted in an interview

## Key constraint
Original, independently understood implementation. Not a reference project clone.
Interview framing: inspired by a hackathon project built with a team, rebuilt
solo to go deeper, called ThreatLens.
