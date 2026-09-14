# Scope and safety

Use these rules before any network scan.

## Minimum scope record

Record:

- `authorization.confirmed`: explicit boolean acknowledgement.
- `authorization.type`: `owned` or `bug-bounty`.
- `authorization.program`: program or owner name.
- `authorization.rules_url`: required source of the rules for `bug-bounty` targets.
- `authorization.valid_until`: optional ISO date; reject expired authorization.
- `automation_allowed`: whether automated scanners are explicitly allowed.
- `allowed_targets`: exact hosts, URLs, or leftmost-label wildcards.
- `excluded_targets`: exclusions that override every allow rule.
- `max_requests_per_second`: required program cap; V1 additionally caps it at 10.
- `max_concurrency`: required program cap; V1 additionally caps it at 3.

Supported wildcard form is only `*.example.com`. It matches a subdomain such as `api.example.com`, not the apex `example.com`. V1 does not accept CIDR ranges, arbitrary globbing, IP ranges, or a wildcard scan target.

## Decision rules

1. Apply exclusions before allowances.
2. Match scheme and port when the scope entry specifies them.
3. Treat a non-root path in a scope URL as a path prefix restriction.
4. Never treat organization ownership, DNS similarity, redirects, certificates, analytics identifiers, or shared cloud infrastructure as authorization.
5. Do not scan a discovered asset until it is independently matched against an allow rule.
6. If the platform rules conflict with this skill, follow the stricter limitation.

## V1 network envelope

Allow only HTTP/HTTPS baseline checks against one validated URL at a time. Keep out-of-band interaction, brute force, fuzzing, denial-of-service, intrusive, headless, network-protocol, and code-execution templates disabled. Do not authenticate, create accounts, enumerate users, upload files, submit forms, or test payment flows.

The tool creates evidence for triage; it does not prove exploitability or bounty eligibility.
