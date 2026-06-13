from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .constants import SEVERITY_ORDER
from .models import Finding, ScanResult
from .policy import Policy
from .reports import apply_vulnerability_baseline, to_cyclonedx, to_html_report, to_sarif, to_spdx
from .scanners import SCANNERS
from .vulnerability_intel import load_local_vulnerability_findings

def run_scan_pipeline(
    root: Path,
    policy_arg: str | None,
    out: str,
    fail_on: str,
    online_audit: bool,
    sarif: str,
    cyclonedx: str,
    spdx: str,
    html: str,
):
    policy=Policy.load(root, policy_arg)
    findings=[]; components=[]
    for scanner in SCANNERS:
        f,c=scanner.scan(root, policy)
        findings.extend(f); components.extend(c)
    findings.extend(load_local_vulnerability_findings(root, components))
    if online_audit:
        findings.extend(run_online_audits(root))
    findings = apply_vulnerability_baseline(root, policy, findings)
    threshold=SEVERITY_ORDER[fail_on]
    blocking=[x for x in findings if SEVERITY_ORDER.get(x.severity,0)>=threshold and x.severity!="INFO"]
    result=ScanResult(ok=not blocking, findings=findings, sbom={"bomFormat":"SafeDeps-SBOM-lite","components":components})
    outdir=root/out
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir/"safedeps-report.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    (outdir/"safedeps-sbom.json").write_text(json.dumps(result.sbom, indent=2), encoding="utf-8")
    if sarif:
        sarif_path = root / sarif
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(to_sarif(result), indent=2), encoding="utf-8")
    if cyclonedx:
        cdx_path = root / cyclonedx
        cdx_path.parent.mkdir(parents=True, exist_ok=True)
        cdx_path.write_text(json.dumps(to_cyclonedx(result), indent=2), encoding="utf-8")
    if spdx:
        spdx_path = root / spdx
        spdx_path.parent.mkdir(parents=True, exist_ok=True)
        spdx_path.write_text(json.dumps(to_spdx(result), indent=2), encoding="utf-8")
    if html:
        html_path = root / html
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(to_html_report(result, fail_on), encoding="utf-8")
    return result, outdir

def run_online_audits(root: Path):
    findings=[]
    if (root/"package.json").exists():
        try:
            proc=subprocess.run(["npm","audit","--json"],cwd=root,text=True,capture_output=True,timeout=60)
            if proc.stdout:
                data=json.loads(proc.stdout)
                vulns=data.get("metadata",{}).get("vulnerabilities",{})
                if any(vulns.get(k,0) for k in ["critical","high"]):
                    findings.append(Finding("HIGH","npm","NPM_AUDIT",f"npm audit reports high/critical vulnerabilities: {vulns}",fix="Run npm audit and upgrade/remediate."))
        except Exception as e:
            findings.append(Finding("LOW","npm","AUDIT_UNAVAILABLE",f"npm audit could not run: {e}"))
    return findings

