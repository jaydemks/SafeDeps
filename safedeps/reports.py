from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__
from .constants import SEVERITY_ORDER
from .models import Finding, ScanResult

def apply_vulnerability_baseline(root: Path, policy: Policy, findings: list[Finding]) -> list[Finding]:
    if not policy.data.get("enable_vulnerability_baseline", True):
        return findings
    baseline_file = str(policy.data.get("vulnerability_baseline_file", ".safedeps/vuln-baseline.json")).strip()
    if not baseline_file:
        return findings
    path = root / baseline_file
    if not path.exists():
        return findings
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return findings
    entries = data.get("suppress", [])
    if not isinstance(entries, list):
        return findings
    suppressed = set()
    today = datetime.now(timezone.utc).date()
    for e in entries:
        if not isinstance(e, dict):
            continue
        expires = str(e.get("expires", "")).strip()
        if expires:
            try:
                if datetime.fromisoformat(expires).date() < today:
                    continue
            except Exception:
                # Invalid expiration values are ignored (entry treated as active)
                pass
        suppressed.add(_finding_fingerprint_from_dict(e))
    return [f for f in findings if finding_fingerprint(f) not in suppressed]

def finding_fingerprint(f: Finding):
    return _finding_fingerprint(f.manager, f.rule, f.package or "", f.file or "")

def _finding_fingerprint_from_dict(d: dict):
    return _finding_fingerprint(
        str(d.get("manager", "")),
        str(d.get("rule", "")),
        str(d.get("package", "")),
        str(d.get("file", "")),
    )

def _finding_fingerprint(manager: str, rule: str, package: str, file: str):
    return f"{manager.lower()}|{rule.upper()}|{package.lower()}|{file}"

def to_sarif(result: ScanResult):
    rule_ids = sorted({f"{f.manager}:{f.rule}" for f in result.findings})
    rules = []
    for rid in rule_ids:
        manager, rule = rid.split(":", 1)
        rules.append({
            "id": rid,
            "name": rule,
            "shortDescription": {"text": f"{manager} {rule}"},
            "helpUri": "https://github.com/",
        })
    sarif_results = []
    for f in result.findings:
        rid = f"{f.manager}:{f.rule}"
        entry = {
            "ruleId": rid,
            "level": _sarif_level(f.severity),
            "message": {"text": f.message},
        }
        if f.file:
            entry["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                }
            }]
        sarif_results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SafeDeps", "semanticVersion": __version__, "rules": rules}},
            "invocations": [{"executionSuccessful": result.ok}],
            "results": sarif_results,
        }],
    }

def _sarif_level(severity: str):
    if severity in ("CRITICAL", "HIGH"):
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"

def to_cyclonedx(result: ScanResult):
    unique = _unique_components(result.sbom.get("components", []))
    components = []
    for c in unique:
        name = str(c.get("name", "")).strip()
        if not name:
            continue
        version = str(c.get("version", "")).strip()
        manager = str(c.get("manager", "")).strip()
        scope = str(c.get("scope", "")).strip()
        component = {
            "type": "library",
            "name": name,
            "bom-ref": _component_ref(manager, name, version, scope),
        }
        if version:
            component["version"] = version
        if manager:
            component["purl"] = _purl_for(manager, name, version)
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": f"urn:uuid:safedeps-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": [{
                "vendor": "SafeDeps",
                "name": "safedeps",
                "version": __version__,
            }]
        },
        "components": components,
    }

def _purl_for(manager: str, name: str, version: str):
    if manager == "npm":
        return f"pkg:npm/{name}{'@' + version if version else ''}"
    if manager == "pip":
        return f"pkg:pypi/{name}{'@' + version if version else ''}"
    if manager == "nuget":
        return f"pkg:nuget/{name}{'@' + version if version else ''}"
    return f"pkg:generic/{name}{'@' + version if version else ''}"

def to_spdx(result: ScanResult):
    unique = _unique_components(result.sbom.get("components", []))
    packages = []
    for idx, c in enumerate(unique, start=1):
        name = str(c.get("name", "")).strip()
        if not name:
            continue
        version = str(c.get("version", "")).strip()
        manager = str(c.get("manager", "")).strip()
        pkg = {
            "SPDXID": f"SPDXRef-Package-{idx}",
            "name": name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }
        if version:
            pkg["versionInfo"] = version
        if manager:
            pkg["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": _purl_for(manager, name, version),
            }]
        packages.append(pkg)
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "safedeps-sbom",
        "documentNamespace": "https://safedeps.local/spdx/safedeps-sbom",
        "creationInfo": {
            "creators": ["Tool: safedeps"],
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "packages": packages,
    }

def _unique_components(components):
    seen=set()
    out=[]
    for c in components:
        manager=str(c.get("manager","")).strip()
        name=str(c.get("name","")).strip().lower()
        version=str(c.get("version","")).strip()
        scope=str(c.get("scope","")).strip()
        key=(manager,name,version,scope)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out

def _component_ref(manager: str, name: str, version: str, scope: str):
    base = _purl_for(manager or "generic", name, version)
    return f"{base}#{scope}" if scope else base

def to_html_report(result: ScanResult, fail_on: str):
    status = "PASS" if result.ok else "FAIL"
    findings_html = []
    for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
        findings_html.append(
            "<tr>"
            f"<td>{_html_escape(f.severity)}</td>"
            f"<td>{_html_escape(f.manager)}</td>"
            f"<td>{_html_escape(f.rule)}</td>"
            f"<td>{_html_escape(f.package)}</td>"
            f"<td>{_html_escape(f.file)}</td>"
            f"<td>{_html_escape(f.message)}</td>"
            "</tr>"
        )
    if not findings_html:
        findings_html.append("<tr><td colspan=\"6\">No findings.</td></tr>")
    components_count = len(result.sbom.get("components", []))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SafeDeps Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; color: #1a1a1a; }}
    h1 {{ margin: 0 0 12px; }}
    .meta {{ margin-bottom: 20px; }}
    .status-pass {{ color: #0a7f2e; font-weight: 700; }}
    .status-fail {{ color: #a30000; font-weight: 700; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d8d8d8; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f6f7f9; }}
  </style>
</head>
<body>
  <h1>SafeDeps Scan Report</h1>
  <div class="meta">
    <div>Status: <span class="status-{'pass' if result.ok else 'fail'}">{status}</span></div>
    <div>Fail threshold: {fail_on}</div>
    <div>Findings: {len(result.findings)}</div>
    <div>Components: {components_count}</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Manager</th>
        <th>Rule</th>
        <th>Package</th>
        <th>File</th>
        <th>Message</th>
      </tr>
    </thead>
    <tbody>
      {''.join(findings_html)}
    </tbody>
  </table>
</body>
</html>
"""

def _html_escape(value: str):
    text = str(value or "")
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))

def _js_escape(value: str):
    text = str(value or "")
    return (text.replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\n", "\\n")
                .replace("\r", "\\r"))

def print_summary(result, fail_on, outdir):
    print("\nSafeDeps scan")
    print(f"Status: {'PASS' if result.ok else 'FAIL'}   fail-on: {fail_on}")
    print(f"Findings: {len(result.findings)}   Components: {len(result.sbom.get('components', []))}")
    for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity,0), reverse=True):
        loc=f" [{f.file}]" if f.file else ""
        pkg=f" {f.package}" if f.package else ""
        print(f"- {f.severity} {f.manager}/{f.rule}{pkg}{loc}: {f.message}")
        if f.fix: print(f"  fix: {f.fix}")
    print(f"\nArtifacts: {outdir/'safedeps-report.json'} | {outdir/'safedeps-sbom.json'}")

