#!/usr/bin/env python3
"""Build one sanitized platform-oriented vulnerability report draft."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


HEADINGS = {
    "hackerone": ("Summary", "Steps to reproduce", "Impact", "Remediation"),
    "bugcrowd": ("Overview", "Proof of concept", "Security impact", "Suggested fix"),
    "butian": ("漏洞概述", "复现步骤", "安全影响", "修复建议"),
}


def clean(value: object) -> str:
    text = str(value or "").strip()
    return text or "[Complete after manual validation]"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--platform", choices=sorted(HEADINGS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--draft", action="store_true", help="allow an explicitly unverified draft")
    args = parser.parse_args()

    data = json.loads(args.input.read_text(encoding="utf-8"))
    finding = next((f for f in data.get("findings", []) if f.get("id") == args.finding_id), None)
    if not finding:
        raise SystemExit(f"Finding not found: {args.finding_id}")
    confirmed = finding.get("status") == "confirmed"
    if not confirmed and not args.draft:
        raise SystemExit("Finding is not confirmed. Validate it or use --draft to keep an unverified warning.")

    summary_h, steps_h, impact_h, fix_h = HEADINGS[args.platform]
    warning = "" if confirmed else "> **UNVERIFIED DRAFT — DO NOT SUBMIT UNTIL MANUALLY VALIDATED**\n\n"
    steps = finding.get("reproduction_steps") or []
    rendered_steps = "\n".join(f"{i}. {clean(step)}" for i, step in enumerate(steps, 1)) or "1. [Add minimal, sanitized reproduction steps]"
    report = f"""{warning}# {clean(finding.get('title'))}

**Target:** {clean(finding.get('target'))}  
**Suggested severity:** {clean(finding.get('severity'))}  
**Finding ID:** {finding.get('id')}

## {summary_h}

{clean(finding.get('notes'))}

## {steps_h}

{rendered_steps}

**Expected result:** {clean(finding.get('expected_result'))}

**Actual result:** {clean(finding.get('actual_result'))}

**Sanitized evidence:** {clean(finding.get('evidence'))}

## {impact_h}

{clean(finding.get('impact'))}

## {fix_h}

{clean(finding.get('remediation'))}

---

Automation assisted initial discovery. All claims and evidence must be manually verified against the program rules before submission.
"""
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(str(args.output))


if __name__ == "__main__":
    main()
