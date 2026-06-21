from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .constants import SEVERITY_ORDER
from .models import Finding, ScanResult
from .package_managers import DEFAULT_PACKAGE_MANAGER_ADAPTERS
from .policy import Policy
from .reports import apply_vulnerability_baseline, write_scan_outputs
from .vulnerability_intel import load_local_vulnerability_findings

PACKAGE_MANAGER_ADAPTERS = DEFAULT_PACKAGE_MANAGER_ADAPTERS

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
    for adapter in PACKAGE_MANAGER_ADAPTERS:
        f,c=adapter.scan(root, policy)
        findings.extend(f); components.extend(c)
    findings.extend(load_local_vulnerability_findings(root, components, policy))
    if online_audit:
        findings.extend(run_online_audits(root))
    findings = apply_vulnerability_baseline(root, policy, findings)
    threshold=SEVERITY_ORDER[fail_on]
    blocking=[x for x in findings if SEVERITY_ORDER.get(x.severity,0)>=threshold and x.severity!="INFO"]
    result=ScanResult(ok=not blocking, findings=findings, sbom={"bomFormat":"SafeDeps-SBOM-lite","components":components})
    outdir = write_scan_outputs(
        result,
        root,
        out,
        fail_on=fail_on,
        sarif=sarif,
        cyclonedx=cyclonedx,
        spdx=spdx,
        html=html,
    )
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
