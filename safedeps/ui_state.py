from __future__ import annotations

import json
from pathlib import Path

from .constants import SEVERITY_ORDER


def default_ui_state(scan_path: Path, fail_on: str):
    return {
        "path": str(scan_path),
        "fail_on": fail_on,
        "out": "security-artifacts",
        "policy": "",
        "sarif": "",
        "cyclonedx": "",
        "spdx": "",
        "html": "",
        "online_audit": False,
        "rule": "",
        "report": "security-artifacts/safedeps-report.json",
        "baseline_output": ".safedeps/vuln-baseline.json",
        "baseline_file": ".safedeps/vuln-baseline.json",
        "manager": "",
        "approve_rule": "",
        "package": "",
        "file_value": "",
        "expires": "",
        "vuln_feed_json": "",
        "metadata_cache_json": "",
        "dependency_output": "",
    }

def _ui_state_from_form(form: dict, scan_path: Path, fail_on: str):
    state = default_ui_state(scan_path, fail_on)
    state.update({
        "path": str(scan_path),
        "fail_on": fail_on if fail_on in SEVERITY_ORDER else "HIGH",
        "out": (form.get("out", [state["out"]])[0] or state["out"]).strip(),
        "policy": (form.get("policy", [""])[0] or "").strip(),
        "sarif": (form.get("sarif", [""])[0] or "").strip(),
        "cyclonedx": (form.get("cyclonedx", [""])[0] or "").strip(),
        "spdx": (form.get("spdx", [""])[0] or "").strip(),
        "html": (form.get("html", [""])[0] or "").strip(),
        "online_audit": form.get("online_audit", ["off"])[0] == "on",
        "rule": (form.get("rule", [""])[0] or "").strip().upper(),
        "report": (form.get("report", [state["report"]])[0] or state["report"]).strip(),
        "baseline_output": (form.get("baseline_output", [state["baseline_output"]])[0] or state["baseline_output"]).strip(),
        "baseline_file": (form.get("baseline_file", [state["baseline_file"]])[0] or state["baseline_file"]).strip(),
        "manager": (form.get("manager", [""])[0] or "").strip(),
        "approve_rule": (form.get("approve_rule", [""])[0] or "").strip().upper(),
        "package": (form.get("package", [""])[0] or "").strip(),
        "file_value": (form.get("file_value", [""])[0] or "").strip(),
        "expires": (form.get("expires", [""])[0] or "").strip(),
        "vuln_feed_json": (form.get("vuln_feed_json", [""])[0] or "").strip(),
        "metadata_cache_json": (form.get("metadata_cache_json", [""])[0] or "").strip(),
    })
    return state

def load_intelligence_into_state(state: dict, root: Path):
    vuln_path = root / ".safedeps" / "vuln-feed.json"
    meta_path = root / ".safedeps" / "metadata-cache.json"
    if not state.get("vuln_feed_json"):
        if vuln_path.exists():
            state["vuln_feed_json"] = vuln_path.read_text(encoding="utf-8")
        else:
            state["vuln_feed_json"] = json.dumps({"vulnerabilities": [], "vulnerabilities_osv": []}, indent=2)
    if not state.get("metadata_cache_json"):
        if meta_path.exists():
            state["metadata_cache_json"] = meta_path.read_text(encoding="utf-8")
        else:
            state["metadata_cache_json"] = json.dumps({"packages": []}, indent=2)
    return state

def create_intelligence_templates(root: Path):
    d = root / ".safedeps"
    d.mkdir(parents=True, exist_ok=True)
    vuln_path = d / "vuln-feed.json"
    meta_path = d / "metadata-cache.json"
    if not vuln_path.exists():
        vuln_path.write_text(json.dumps({"vulnerabilities": [], "vulnerabilities_osv": []}, indent=2), encoding="utf-8")
    if not meta_path.exists():
        meta_path.write_text(json.dumps({"packages": []}, indent=2), encoding="utf-8")

def save_intelligence_from_state(root: Path, state: dict):
    d = root / ".safedeps"
    d.mkdir(parents=True, exist_ok=True)
    vuln_raw = state.get("vuln_feed_json", "").strip()
    meta_raw = state.get("metadata_cache_json", "").strip()
    if not vuln_raw:
        raise ValueError("Vulnerability feed JSON cannot be empty.")
    if not meta_raw:
        raise ValueError("Metadata cache JSON cannot be empty.")
    try:
        vuln_data = json.loads(vuln_raw)
    except Exception as e:
        raise ValueError(f"Invalid vulnerability feed JSON: {e}") from e
    try:
        meta_data = json.loads(meta_raw)
    except Exception as e:
        raise ValueError(f"Invalid metadata cache JSON: {e}") from e
    if not isinstance(vuln_data, dict):
        raise ValueError("Vulnerability feed must be a JSON object.")
    if not isinstance(meta_data, dict):
        raise ValueError("Metadata cache must be a JSON object.")
    (d / "vuln-feed.json").write_text(json.dumps(vuln_data, indent=2), encoding="utf-8")
    (d / "metadata-cache.json").write_text(json.dumps(meta_data, indent=2), encoding="utf-8")

