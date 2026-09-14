#!/usr/bin/env python3
"""Normalize Nuclei, Semgrep, and redacted Gitleaks output for human triage."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable


SEVERITY = {
    "error": "high",
    "warning": "medium",
    "info": "info",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "unknown": "unknown",
}


def stable_id(detector: str, rule: str, target: str) -> str:
    digest = hashlib.sha256(f"{detector}|{rule}|{target}".encode()).hexdigest()[:12]
    return f"bb-{digest}"


def base(detector: str, rule: str, title: str, severity: str, target: str, evidence: str) -> dict:
    return {
        "id": stable_id(detector, rule, target),
        "title": title or rule,
        "severity": SEVERITY.get(str(severity).lower(), "unknown"),
        "target": target,
        "detector": detector,
        "rule_id": rule,
        "evidence": evidence,
        "status": "needs-manual-validation",
        "confidence": "scanner-lead",
        "reproduction_steps": [],
        "expected_result": "",
        "actual_result": "",
        "impact": "",
        "remediation": "",
        "notes": "",
    }


def nuclei_findings(path: Path) -> Iterable[dict]:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        info = item.get("info") or {}
        rule = str(item.get("template-id") or item.get("template") or "nuclei")
        target = str(item.get("matched-at") or item.get("host") or "")
        matcher = str(item.get("matcher-name") or "")
        extracted = item.get("extracted-results") or []
        evidence = "; ".join(str(v) for v in extracted[:5])
        if matcher:
            evidence = f"matcher={matcher}" + (f"; {evidence}" if evidence else "")
        yield base("nuclei", rule, str(info.get("name") or rule), str(info.get("severity") or "unknown"), target, evidence)


def semgrep_findings(path: Path) -> Iterable[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data.get("results", []):
        extra = item.get("extra") or {}
        rule = str(item.get("check_id") or "semgrep")
        line = (item.get("start") or {}).get("line")
        target = f"{item.get('path', '')}:{line or ''}".rstrip(":")
        yield base("semgrep", rule, str(extra.get("message") or rule), str(extra.get("severity") or "unknown"), target, f"rule={rule}")


def gitleaks_findings(path: Path) -> Iterable[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data if isinstance(data, list) else []:
        rule = str(item.get("RuleID") or "gitleaks")
        target = f"{item.get('File', '')}:{item.get('StartLine', '')}".rstrip(":")
        yield base("gitleaks", rule, str(item.get("Description") or rule), "high", target, "Secret-like value detected; value redacted")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nuclei", type=Path)
    parser.add_argument("--semgrep", type=Path)
    parser.add_argument("--gitleaks", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    findings: list[dict] = []
    for path, loader in ((args.nuclei, nuclei_findings), (args.semgrep, semgrep_findings), (args.gitleaks, gitleaks_findings)):
        if path and path.exists():
            findings.extend(loader(path))

    deduped = {item["id"]: item for item in findings}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    ordered = sorted(deduped.values(), key=lambda x: (severity_rank.get(x["severity"], 9), x["target"], x["title"]))
    result = {
        "schema_version": 1,
        "notice": "Scanner leads only. Human validation is required before submission.",
        "summary": {"raw": len(findings), "deduplicated": len(ordered)},
        "findings": ordered,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(ordered)} findings to {args.output}")


if __name__ == "__main__":
    main()
