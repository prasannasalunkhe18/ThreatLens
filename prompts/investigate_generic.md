## Investigation lens: GENERIC (no CWE-specific skill matched)

No hand-written skill covers this finding's CWE, so investigate from first
security principles. The specific rule, library, or API name is irrelevant —
judge whether the underlying security property is violated on a reachable path.

Apply this universal source → sink → mitigation reasoning:

1. **Source** — Is there attacker-controllable input involved? Classify it:
   external (HTTP request params/body/headers/uploaded files, message payloads)
   vs. internal/trusted (hardcoded values, server-controlled config). If nothing
   attacker-controllable feeds this location, it is almost certainly a
   FALSE_POSITIVE.
2. **Sink** — What is the dangerous operation at the flagged location (code or
   command execution, query construction, outbound request, file path access,
   deserialization, auth decision, response rendering)? State what property must
   hold for it to be safe (e.g. data/code separation, verified identity,
   validated destination, safe/least-privilege parsing).
3. **Flow** — Trace hop-by-hop from source to sink, naming each file/function.
   If any hop is missing from the provided context, say so.
4. **Mitigation** — Between source and sink, is the required safety property
   established? Classify any control as: strong (allowlist / parameterization /
   context-correct encoding / verified signature), weak (denylist / regex strip
   / partial check — note bypass candidates), or absent.
5. **Reachability** — Is the sink actually reachable by an attacker (route
   registered, not dead code, not gated by an upstream control that already
   neutralizes the input)?

Verdict guidance: TRUE_POSITIVE only when attacker-controllable input reaches the
dangerous sink with the safety property absent or bypassable, on a reachable
path. Otherwise FALSE_POSITIVE. When context is insufficient to confirm a hop,
lean FALSE_POSITIVE and lower confidence — state what was missing.
