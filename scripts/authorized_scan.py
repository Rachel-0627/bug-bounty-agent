#!/usr/bin/env python3
"""Scope-gated wrappers for conservative V1 web and source-code scans."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse


MAX_RATE = 10
MAX_CONCURRENCY = 3


def fail(message: str, code: int = 2) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)


def load_scope(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"Cannot read valid scope JSON: {exc}")
    auth = data.get("authorization") or {}
    if auth.get("confirmed") is not True:
        fail("authorization.confirmed must be true")
    auth_type = auth.get("type")
    if auth_type not in {"owned", "bug-bounty"}:
        fail("authorization.type must be 'owned' or 'bug-bounty'")
    if not str(auth.get("program", "")).strip():
        fail("authorization.program is required")
    if auth_type == "bug-bounty" and not str(auth.get("rules_url", "")).strip():
        fail("authorization.rules_url is required for bug-bounty targets")
    valid_until = auth.get("valid_until")
    if valid_until:
        try:
            expiry = dt.date.fromisoformat(valid_until)
        except ValueError:
            fail("authorization.valid_until must use YYYY-MM-DD")
        if expiry < dt.date.today():
            fail(f"authorization expired on {expiry.isoformat()}")
    allowed = data.get("allowed_targets")
    if not isinstance(allowed, list) or not allowed:
        fail("allowed_targets must be a non-empty list")
    excluded = data.get("excluded_targets", [])
    if not isinstance(excluded, list):
        fail("excluded_targets must be a list")
    for field in ("max_requests_per_second", "max_concurrency"):
        value = data.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail(f"{field} must be a positive integer")
    return data


def parse_url(value: str, *, permit_wildcard: bool) -> tuple[str | None, str, int | None, str]:
    candidate = value.strip()
    if not candidate:
        fail("empty target or scope entry")
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    scheme = parsed.scheme.lower() or None
    if scheme and scheme not in {"http", "https"}:
        fail(f"unsupported scheme in {value!r}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        fail(f"credentials, query strings, and fragments are not allowed in scope entries: {value!r}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        fail(f"missing host in {value!r}")
    if "*" in host:
        if not permit_wildcard or not host.startswith("*.") or "*" in host[2:]:
            fail(f"only a leftmost '*.' wildcard is supported: {value!r}")
    try:
        port = parsed.port
    except ValueError:
        fail(f"invalid port in {value!r}")
    path = parsed.path or "/"
    if ".." in unquote(path).split("/"):
        fail(f"dot-segment paths are not allowed: {value!r}")
    return scheme, host, port, path


def pattern_matches(pattern: str, target: str) -> bool:
    p_scheme, p_host, p_port, p_path = parse_url(pattern, permit_wildcard=True)
    t_scheme, t_host, t_port, t_path = parse_url(target, permit_wildcard=False)
    if p_scheme and p_scheme != t_scheme:
        return False
    if p_scheme:
        p_effective_port = p_port or (443 if p_scheme == "https" else 80)
        t_effective_port = t_port or (443 if t_scheme == "https" else 80)
        if p_effective_port != t_effective_port:
            return False
    elif p_port is not None and p_port != t_port:
        return False
    if p_host.startswith("*."):
        suffix = p_host[1:]
        if not t_host.endswith(suffix) or t_host == p_host[2:]:
            return False
    elif p_host != t_host:
        return False
    if p_path != "/" and not t_path.startswith(p_path):
        return False
    return True


def validate_target(scope: dict, target: str) -> None:
    parse_url(target, permit_wildcard=False)
    if any(pattern_matches(p, target) for p in scope.get("excluded_targets", [])):
        fail(f"target is explicitly excluded: {target}")
    if not any(pattern_matches(p, target) for p in scope["allowed_targets"]):
        fail(f"target does not match an allowed scope entry: {target}")


def run_logged(command: list[str], stdout_path: Path, stderr_path: Path) -> int:
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
    return result.returncode


def web_scan(args: argparse.Namespace) -> None:
    if not args.ack_authorized:
        fail("pass --ack-authorized only after confirming written scope")
    scope = load_scope(args.scope)
    validate_target(scope, args.target)
    if scope.get("automation_allowed") is not True:
        fail("scope does not explicitly allow automated scanning")
    nuclei = shutil.which("nuclei")
    if not nuclei:
        fail("Nuclei is not installed; no network request was made", 3)
    output = args.output.resolve()
    raw = output / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    rate = min(MAX_RATE, scope["max_requests_per_second"])
    concurrency = min(MAX_CONCURRENCY, scope["max_concurrency"])
    result_path = raw / "nuclei.jsonl"
    command = [
        nuclei,
        "-u", args.target,
        "-jsonl-export", str(result_path),
        "-rate-limit", str(rate),
        "-concurrency", str(concurrency),
        "-bulk-size", "1",
        "-timeout", "10",
        "-retries", "1",
        "-no-interactsh",
        "-disable-update-check",
        "-silent",
        "-tags", "tech,ssl,misconfig,exposure",
        "-exclude-tags", "dos,fuzz,bruteforce,intrusive,headless,network,code",
    ]
    manifest = {
        "mode": "web",
        "target": args.target,
        "program": scope["authorization"]["program"],
        "rate_limit": rate,
        "concurrency": concurrency,
        "command": command,
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    (output / "scan-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    code = run_logged(command, raw / "nuclei.stdout.log", raw / "nuclei.stderr.log")
    if code != 0:
        fail(f"Nuclei exited with status {code}; inspect {raw / 'nuclei.stderr.log'}", code)
    print(str(result_path))


def code_scan(args: argparse.Namespace) -> None:
    if not args.ack_authorized:
        fail("pass --ack-authorized only for source you own or may assess")
    source = args.source.resolve()
    if not source.is_dir():
        fail(f"source directory does not exist: {source}")
    output = args.output.resolve()
    raw = output / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict] = {}

    semgrep = shutil.which("semgrep")
    if semgrep:
        path = raw / "semgrep.json"
        cmd = [semgrep, "scan", "--config", "auto", "--json", "--output", str(path), str(source)]
        code = run_logged(cmd, raw / "semgrep.stdout.log", raw / "semgrep.stderr.log")
        results["semgrep"] = {"exit_code": code, "output": str(path)}
    else:
        results["semgrep"] = {"skipped": "not installed"}

    gitleaks = shutil.which("gitleaks")
    if gitleaks:
        path = raw / "gitleaks.json"
        cmd = [gitleaks, "detect", "--source", str(source), "--report-format", "json", "--report-path", str(path), "--redact", "--no-banner"]
        code = run_logged(cmd, raw / "gitleaks.stdout.log", raw / "gitleaks.stderr.log")
        results["gitleaks"] = {"exit_code": code, "output": str(path)}
    else:
        results["gitleaks"] = {"skipped": "not installed"}

    manifest = {
        "mode": "code",
        "source": str(source),
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "tools": results,
    }
    (output / "scan-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if all("skipped" in result for result in results.values()):
        fail("Neither Semgrep nor Gitleaks is installed; no scan ran", 3)
    print(json.dumps(results, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="validate one URL against a scope file")
    validate.add_argument("--scope", type=Path, required=True)
    validate.add_argument("--target", required=True)

    web = sub.add_parser("web", help="run a conservative Nuclei baseline")
    web.add_argument("--scope", type=Path, required=True)
    web.add_argument("--target", required=True)
    web.add_argument("--output", type=Path, required=True)
    web.add_argument("--ack-authorized", action="store_true")

    code = sub.add_parser("code", help="run local Semgrep and Gitleaks scans")
    code.add_argument("--source", type=Path, required=True)
    code.add_argument("--output", type=Path, required=True)
    code.add_argument("--ack-authorized", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "validate":
        scope = load_scope(args.scope)
        validate_target(scope, args.target)
        print("AUTHORIZED: target matches the supplied scope")
    elif args.command == "web":
        web_scan(args)
    else:
        code_scan(args)


if __name__ == "__main__":
    main()
