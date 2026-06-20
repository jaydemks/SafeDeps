from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .constants import RULE_EXPLAINERS
from .reports import _finding_fingerprint_from_dict

def upsert_approval_entry(root: Path, baseline_rel: str, manager: str, rule: str, package: str, file_value: str, expires: str):
    if not manager or not rule:
        raise ValueError("manager and rule are required")
    try:
        datetime.fromisoformat(expires).date()
    except Exception:
        raise ValueError("Invalid expires format. Use YYYY-MM-DD.") from None
    baseline_path = root / baseline_rel
    data: dict[str, Any] = {"suppress": []}
    if baseline_path.exists():
        try:
            data = json.loads(baseline_path.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid baseline JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("Invalid baseline format: expected JSON object")
    suppress = data.get("suppress", [])
    if not isinstance(suppress, list):
        raise ValueError("Invalid baseline format: suppress must be a list")
    entry = {"manager": manager, "rule": rule, "package": package, "file": file_value, "expires": expires}
    fingerprint = _finding_fingerprint_from_dict(entry)
    for existing in suppress:
        if isinstance(existing, dict) and _finding_fingerprint_from_dict(existing) == fingerprint:
            existing["expires"] = expires
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return True, f"{manager}/{rule} package={package or '*'} file={file_value or '*'} expires={expires}"
    suppress.append(entry)
    data["suppress"] = suppress
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return False, f"{manager}/{rule} package={package or '*'} file={file_value or '*'} expires={expires}"

def cmd_explain(args):
    rule = str(args.rule).strip().upper()
    text = RULE_EXPLAINERS.get(rule)
    if not text:
        print(f"Unknown finding rule: {rule}")
        print("Tip: run scan and use one of the emitted rule identifiers.")
        return 2
    print(f"{rule}")
    print(text)
    return 0

def write_baseline_file(root: Path, report_rel: str, output_rel: str):
    report_path = root / report_rel
    output_path = root / output_rel
    if not report_path.exists():
        raise ValueError(f"Missing report file: {report_path}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid report JSON: {e}") from e
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("Invalid report format: findings must be a list")
    suppress = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        suppress.append(
            {
                "manager": str(f.get("manager", "")),
                "rule": str(f.get("rule", "")),
                "package": str(f.get("package", "")),
                "file": str(f.get("file", "")),
            }
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps({"suppress": suppress}, indent=2), encoding="utf-8")
    return len(suppress), output_path

def cmd_baseline(args):
    root = Path(args.path).resolve()
    try:
        count, output_path = write_baseline_file(root, args.report, args.output)
    except Exception as e:
        print(str(e))
        return 2
    print(f"Baseline written: {output_path} ({count} entries)")
    return 0

def cmd_approve(args):
    root = Path(args.path).resolve()
    baseline_path = root / args.baseline
    manager = str(args.manager).strip()
    rule = str(args.rule).strip().upper()
    package = str(args.package).strip()
    file_value = str(args.file).strip()
    expires = str(args.expires).strip()
    if not manager or not rule:
        print("manager and rule are required")
        return 2
    try:
        datetime.fromisoformat(expires).date()
    except Exception:
        print("Invalid expires format. Use YYYY-MM-DD.")
        return 2
    data = {"suppress": []}
    if baseline_path.exists():
        try:
            data = json.loads(baseline_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"Invalid baseline JSON: {e}")
            return 2
    if not isinstance(data, dict):
        print("Invalid baseline format: expected JSON object")
        return 2
    suppress = data.get("suppress", [])
    if not isinstance(suppress, list):
        print("Invalid baseline format: suppress must be a list")
        return 2
    entry = {
        "manager": manager,
        "rule": rule,
        "package": package,
        "file": file_value,
        "expires": expires,
    }
    fingerprint = _finding_fingerprint_from_dict(entry)
    for existing in suppress:
        if isinstance(existing, dict) and _finding_fingerprint_from_dict(existing) == fingerprint:
            existing["expires"] = expires
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"Updated approval: {manager}/{rule} package={package or '*'} file={file_value or '*'} expires={expires}")
            return 0
    suppress.append(entry)
    data["suppress"] = suppress
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Added approval: {manager}/{rule} package={package or '*'} file={file_value or '*'} expires={expires}")
    return 0
