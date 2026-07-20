# PRD: ThreatLens — PR Vulnerability Triage Agent

## Problem
Static analysis tools (Snyk, Semgrep, etc.) flag security issues on every PR but lack context — high false-positive noise, no understanding of whether a flagged pattern is actually reachable/exploitable in the real code path. Manual review to make that exploitability judgment call doesn't scale with PR volume.

## Goal
Build ThreatLens: an autonomous agent that, given a GitHub PR, reasons about what could go wrong security-wise in the diff, investigates the most plausible threats by tracing actual code paths, and produces a verdict (real vulnerability or false positive) with reasoning — before the code merges.

## Target Use Case
Portfolio/demo project for security engineering interviews (specifically positioned for AI Security Engineer roles). Complementary to — not a copy of — backlog remediation tools (e.g. Snyk+Cursor workflows), since ThreatLens operates at PR-time (pre-merge) rather than backlog-time (post-merge).

## Core Features (in scope)
1. Fetch a PR diff via GitHub API given a PR URL
2. Stage 1: LLM-driven threat modeling — identify plausible threats in the diff, map to CWE categories, decide if deep investigation is warranted
3. Stage 2: LLM-driven investigation — for each flagged threat, trace data flow/reachability using a matched skill (CWE-specific checklist), produce a verdict
4. Structured output: verdict (TRUE_POSITIVE/FALSE_POSITIVE), confidence score, reasoning chain
5. CLI interface: `threatlens pr analyze <PR_URL>`
6. Swappable LLM provider (OpenRouter primary w/ free-model fallback list, Groq secondary) — zero cost

## Out of Scope (v1)
- No live cloud/IaC environment — testing against public vulnerable sample apps only (Juice Shop, WebGoat, DVWA)
- No auto-remediation / auto-fix loop (that's the Snyk+Cursor problem space, not this project's)
- No org-wide/multi-repo search (deferred to optional Week 4)
- No paid LLM usage — free tier only

## Initial Skill Coverage (CWE classes)
- Injection: CWE-89 (SQLi), CWE-78 (Command Injection), CWE-79 (XSS)
- Auth: CWE-287, CWE-306
- SSRF: CWE-918
- Deserialization: CWE-502

## Success Criteria
- Runs end-to-end on a real public PR and produces a sensible threat model + verdict
- At least 3-4 skills implemented and demonstrably distinguishing true vs false positives on test PRs
- Can articulate every design decision unprompted in an interview setting

## Key Constraint
Original, independently understood implementation — not a reference-project clone. Framing for any interview: "inspired by a hackathon project I built with a team, rebuilt solo to go deeper, called it ThreatLens."
