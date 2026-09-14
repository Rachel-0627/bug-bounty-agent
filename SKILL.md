---
name: bug-bounty-agent
description: "Safely orchestrate first-pass bug bounty work for explicitly authorized web targets or source repositories: validate program scope, run low-rate non-intrusive Nuclei or local Semgrep/Gitleaks scans, normalize and deduplicate findings, triage evidence, and draft HackerOne, Bugcrowd, or Butian reports. Use for authorized vulnerability scanning, bug bounty triage, scanner-result review, security finding validation, or bounty report preparation. Do not use for targets without clear authorization, broad internet scanning, exploitation, credential attacks, denial of service, or evasion."
---

# Bug Bounty Agent

Build a conservative first-pass workflow around mature scanners. Treat every scanner match as an unverified lead until its scope, reproducibility, impact, and evidence are established.

## Choose the workflow

- For a public web or API target, use **Web baseline** only after validating written program scope.
- For a local source tree, use **Source audit** after the user confirms ownership or authorization.
- For existing JSON/JSONL scanner output, skip scanning and use **Normalize and triage**.
- For a report request, use **Draft a submission** only for one finding at a time.
- If authorization or scope is missing, perform planning only and ask for the program rules or an explicit statement that the user owns the target.

## Establish authorization

Before any network request:

1. Read `references/scope-and-safety.md` completely.
2. Obtain the program name, rules URL or supplied rules text, allowed targets, exclusions, validity date when present, and whether automated scanning is allowed.
3. Create a scope JSON from `references/scope.example.json`. Never infer wildcard scope from a company name or parent domain.
4. Run `scripts/authorized_scan.py validate --scope <scope.json> --target <url>`.
5. Stop if validation fails. Do not try nearby domains, redirects, ports, IPs, or third-party services.

Treat a user statement that they own a local test system as authorization for that exact system. For a third-party bounty target, require program scope text or a rules URL supplied by the user before active scanning.

## Web baseline

Use this command only when scope validation passes and the program permits automation:

```bash
python3 <skill-dir>/scripts/authorized_scan.py web \
  --scope scope.json \
  --target https://in-scope.example \
  --output scan-output \
  --ack-authorized
```

The wrapper caps rate and concurrency, disables out-of-band callbacks, and excludes denial-of-service, fuzzing, brute-force, intrusive, headless, network, and code-execution template tags. Do not bypass these controls in V1. If Nuclei is unavailable, report the missing dependency and give the official installation command appropriate to the user's OS only after checking current official documentation.

Do not add crawling, subdomain enumeration, authenticated testing, custom payloads, or exploit templates in V1. Follow redirects only after independently confirming the destination is in scope.

## Source audit

Run only against a local source directory the user owns or is authorized to assess:

```bash
python3 <skill-dir>/scripts/authorized_scan.py code \
  --source /absolute/path/to/repository \
  --output scan-output \
  --ack-authorized
```

The wrapper runs Semgrep and Gitleaks when installed. Preserve raw output locally. Never reproduce or expose detected secret values; Gitleaks must remain in redacted mode.

## Normalize and triage

Normalize any available raw outputs:

```bash
python3 <skill-dir>/scripts/normalize_findings.py \
  --nuclei scan-output/raw/nuclei.jsonl \
  --semgrep scan-output/raw/semgrep.json \
  --gitleaks scan-output/raw/gitleaks.json \
  --output scan-output/findings.json
```

Omit inputs that do not exist. Then read `references/triage-and-reporting.md` completely and review each finding in context.

For every finding:

1. Confirm the asset is still in scope.
2. Read the surrounding source or response evidence.
3. Reproduce once using the least invasive request allowed by the program.
4. Record expected versus actual behavior and concrete security impact.
5. Search the current result set for duplicates and shared root causes.
6. Keep `status: needs-manual-validation` unless the evidence independently demonstrates the issue.
7. Change status to `confirmed` only when reproduction, affected target, impact, and sanitized evidence are complete.

Never claim a bounty is likely merely because a scanner assigned high severity. Downgrade or reject version banners, missing headers, generic best-practice gaps, and unproven CVE matches unless the program explicitly rewards them and impact is demonstrated.

## Draft a submission

Generate a single-finding draft:

```bash
python3 <skill-dir>/scripts/build_report.py \
  --input scan-output/findings.json \
  --finding-id <id> \
  --platform hackerone \
  --output submission-draft.md
```

Supported platforms are `hackerone`, `bugcrowd`, and `butian`. The script refuses unconfirmed findings unless `--draft` is supplied; drafts must retain the visible unverified warning. Improve the generated report using the program's actual fields and rules.

Do not submit automatically. Show the final sanitized report to the user and obtain separate confirmation before any external submission. Remove tokens, cookies, personal data, unrelated customer data, and secret values from evidence.

## Stop conditions

Stop active work and explain the blocker when:

- scope is ambiguous, expired, excluded, or redirects off-scope;
- automation is prohibited or rate limits are unknown;
- validation would access another user's data, alter production state, trigger payment/email/SMS, upload a file, or require social engineering;
- the next step involves brute force, credential stuffing, persistence, malware, denial of service, stealth, destructive actions, or bulk scanning;
- a suspected vulnerability cannot be demonstrated without exceeding program rules.

Offer a safe local reproduction plan or report the lead as unverified instead.
