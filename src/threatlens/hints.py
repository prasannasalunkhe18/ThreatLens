"""Optional, non-authoritative investigation hints by CWE.

Hints supplement the generic evidence investigator. They never select a
different investigator and never determine the verdict.
"""

from __future__ import annotations

INVESTIGATION_HINTS: dict[str, list[str]] = {
    "CWE-918": [
        "Check redirect behavior",
        "Check private, loopback, and link-local destinations",
        "Check DNS validation timing (TOCTOU / rebinding)",
        "Check alternate IP encodings and parser disagreement",
        "Check whether destination allowlisting is enforced at request time",
    ],
    "CWE-611": [
        "Check whether external entity / DTD resolution is disabled",
        "Check whether the XML parser follows external references",
    ],
    "CWE-89": [
        "Check parameterized query use",
        "Check string construction and interpolation into SQL",
        "Check whether escaping matches the SQL context",
    ],
    "CWE-78": [
        "Check argument-vector exec vs shell string interpolation",
        "Check whether untrusted input can alter command structure",
    ],
    "CWE-79": [
        "Check context-correct output encoding at the exact sink",
        "Check whether framework auto-escaping applies on this path",
    ],
    "CWE-77": [
        "Check whether untrusted input alters command or query structure",
        "Check for structural separation of data from interpreter input",
    ],
    "CWE-94": [
        "Check dynamic code evaluation sinks",
        "Check whether untrusted data reaches eval/compile/exec constructs",
    ],
    "CWE-95": [
        "Check eval/dynamic execution of attacker-influenced strings",
        "Check whether stored attacker data later reaches an eval sink",
    ],
    "CWE-1336": [
        "Check server-side template evaluation of untrusted input",
        "Check whether the template engine escapes or evaluates expressions",
    ],
    "CWE-943": [
        "Check NoSQL operator injection in query objects",
        "Check whether user input is embedded as query structure",
    ],
    "CWE-502": [
        "Check whether the deserializer is code-capable vs data-only",
        "Check integrity verification before deserialization",
        "Check type allowlists or safe/restricted parse modes",
    ],
    "CWE-287": [
        "Check whether a verified authentication gate runs on this path",
        "Check client-supplied identity fields vs server-verified principal",
    ],
    "CWE-306": [
        "Check for missing authentication on sensitive operations",
        "Confirm auth enforcement at the handler, not only by convention",
    ],
    "CWE-862": [
        "Check missing authorization before privileged actions",
        "Check per-object ownership/ACL checks",
    ],
    "CWE-863": [
        "Check incorrect authorization logic and bypass branches",
        "Check swallowed auth errors and debug bypasses",
    ],
    "CWE-639": [
        "Check attacker-controllable object identifiers (IDOR)",
        "Check authorization keyed on the authenticated principal",
    ],
}


def hints_for_cwes(cwe_ids: list[str]) -> list[str]:
    """Return de-duplicated optional hints for the given CWEs."""
    seen: set[str] = set()
    out: list[str] = []
    for cwe in cwe_ids:
        key = (cwe or "").strip().upper()
        if not key.startswith("CWE-") and key.isdigit():
            key = f"CWE-{key}"
        for hint in INVESTIGATION_HINTS.get(key, []):
            if hint not in seen:
                seen.add(hint)
                out.append(hint)
    return out
