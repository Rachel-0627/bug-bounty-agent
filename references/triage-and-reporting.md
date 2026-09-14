# Triage and reporting

## Confirmation gate

Keep a result unverified unless all five statements are true:

1. The exact affected asset and action are in scope.
2. The behavior is reproducible with a minimal, non-destructive test.
3. The evidence distinguishes the issue from intended behavior or a scanner fingerprint.
4. The impact identifies what an attacker gains, changes, or disrupts.
5. The report contains no secrets, session tokens, personal data, or unrelated customer data.

## Common false positives

- A software version string without proof that the vulnerable component or code path is reachable.
- Missing security headers without an exploitable consequence.
- A reflected string that is contextually encoded and cannot execute.
- HTTP 200 responses containing a generic login or error page.
- Public files intentionally exposed by product design.
- CORS headers without a credentialed cross-origin data read.
- Rate-limit observations based on only a few requests.
- DNS or takeover indicators without safe proof that the resource is claimable and in scope.

## Severity reasoning

Start with demonstrated impact, required privileges, user interaction, affected data, and repeatability. Treat scanner severity as a hint. Prefer the program's severity rubric; otherwise use CVSS only as a supporting estimate and label assumptions.

## Minimum submission

Include:

- concise title with vulnerability type and affected asset;
- exact scoped target;
- summary and prerequisite state;
- numbered reproduction steps using sanitized placeholders;
- expected and actual result;
- concrete security impact;
- minimal evidence with timestamps when useful;
- suggested remediation;
- disclosure that automation helped discovery when platform rules require it.

Submit one root cause per report unless a chain is necessary to demonstrate impact. Never inflate severity, promise exploitability, or hide tool use when disclosure is required.
