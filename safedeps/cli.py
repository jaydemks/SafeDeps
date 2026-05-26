from __future__ import annotations
import argparse, json, os, sys, subprocess, threading, webbrowser
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .policy import Policy, DEFAULT_POLICY
from .scanners import SCANNERS
from .models import ScanResult, Finding
from . import __version__
from . import guard as _guard
from .vulnerability_intel import load_local_vulnerability_findings
from .scanners.metadata_signals import MetadataSignals

SEVERITY_ORDER={"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
RULE_EXPLAINERS = {
    "FLOATING_VERSION": "Dependency version is not pinned exactly. Pin exact versions to reduce supply-chain drift.",
    "UNTRUSTED_INDEX": "Dependency source/registry is not in allowed registries. Use only trusted registries.",
    "DENY_PACKAGE": "Dependency is explicitly denied by policy denylist.",
    "MISSING_LOCKFILE": "Manifest exists but lockfile is missing while lockfiles are required.",
    "KNOWN_VULNERABILITY": "Package/version matches a known vulnerability from configured intelligence sources.",
    "TYPOSQUATTING_RISK": "Package name appears similar to protected/high-value packages and may be typosquatting.",
    "PACKAGE_TOO_NEW": "Package is newer than configured minimum age threshold.",
    "PUBLISHER_CHURN": "Publisher/owner changed too frequently in the configured time window.",
    "MAINTAINER_CHANGE_RISK": "Maintainer ownership changed beyond configured threshold.",
}

def cmd_init(args):
    root=Path(args.path).resolve()
    d=root/".safedeps"
    d.mkdir(exist_ok=True)
    p=d/"policy.json"
    if not p.exists() or args.force:
        p.write_text(json.dumps(DEFAULT_POLICY, indent=2), encoding="utf-8")
    print(f"SafeDeps policy written: {p}")
    return 0

def cmd_scan(args):
    result, outdir = run_scan_pipeline(
        root=Path(args.path).resolve(),
        policy_arg=args.policy,
        out=args.out,
        fail_on=args.fail_on,
        online_audit=args.online_audit,
        sarif=args.sarif,
        cyclonedx=args.cyclonedx,
        spdx=args.spdx,
        html=args.html,
    )
    print_summary(result, args.fail_on, outdir)
    return 0 if result.ok else 2

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

def cmd_doctor(args):
    root=Path(args.path).resolve()
    issues=[]
    warnings=[]
    safedeps_dir=root/".safedeps"
    policy_path=safedeps_dir/"policy.json"
    cache_path=safedeps_dir/"metadata-cache.json"

    if not safedeps_dir.exists():
        issues.append("Missing .safedeps directory. Run: safedeps init")
    if not policy_path.exists():
        issues.append("Missing .safedeps/policy.json. Run: safedeps init")
    else:
        try:
            json.loads(policy_path.read_text(encoding="utf-8"))
        except Exception as e:
            issues.append(f"Invalid policy JSON: {e}")

    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
            if not isinstance(cache, dict):
                issues.append("metadata-cache.json must be a JSON object.")
        except Exception as e:
            issues.append(f"Invalid metadata cache JSON: {e}")
    else:
        warnings.append("No metadata cache found (.safedeps/metadata-cache.json). Age/churn signals will be inactive unless cache is provided.")
    warnings.extend(_python_env_warnings())

    print("\nSafeDeps doctor")
    print(f"Path: {root}")
    if issues:
        print("Status: FAIL")
        for i in issues:
            print(f"- ISSUE: {i}")
    else:
        print("Status: PASS")
    for w in warnings:
        print(f"- WARNING: {w}")
    return 2 if issues else 0

def _python_env_warnings():
    warnings = []
    if sys.version_info < (3, 10):
        warnings.append("Python <3.10 detected. SafeDeps requires Python 3.10+.")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "--version"],
            text=True,
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            warnings.append("pytest is not available in this environment. Install dev deps with: pip install .[dev]")
    except Exception:
        warnings.append("pytest check unavailable. Ensure dev deps are installed with: pip install .[dev]")
    return warnings

def cmd_ui(args):
    host = args.host
    port = args.port
    start_path = Path(args.path).resolve()
    default_fail_on = args.fail_on
    setup_note = ""

    if "Not configured" in get_setup_status(start_path):
        try:
            cmd_setup(argparse.Namespace(path=str(start_path), fail_on=default_fail_on, force=False))
            setup_note = "Auto-setup completed: guard wrappers created for this project."
        except Exception as e:
            setup_note = f"Auto-setup failed: {e}"

    class UIHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/":
                self.send_error(404)
                return
            try:
                initial_result, initial_outdir = run_scan_pipeline(
                    root=start_path,
                    policy_arg=None,
                    out="security-artifacts",
                    fail_on=default_fail_on if default_fail_on in SEVERITY_ORDER else "HIGH",
                    online_audit=False,
                    sarif="",
                    cyclonedx="",
                    spdx="",
                    html="",
                )
                notice = "Initial scan completed."
                if setup_note:
                    notice = f"{setup_note} {notice}"
                body = render_ui_page(start_path, default_fail_on, result=initial_result, outdir=initial_outdir, notice=notice)
            except Exception as e:
                body = render_ui_page(start_path, default_fail_on, error=str(e))
            self._send_html(body)

        def do_POST(self):
            if self.path not in ("/scan", "/explain", "/baseline", "/approve", "/setup", "/intelligence", "/policy", "/guard", "/deps"):
                self.send_error(404)
                return
            content_len = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(content_len).decode("utf-8")
            form = parse_qs(payload)
            scan_path = Path((form.get("path", [str(start_path)])[0] or str(start_path))).resolve()
            fail_on = (form.get("fail_on", [default_fail_on])[0] or default_fail_on).upper()
            ui_state = _ui_state_from_form(form, scan_path, fail_on)
            try:
                if self.path == "/scan":
                    out = form.get("out", ["security-artifacts"])[0] or "security-artifacts"
                    online_audit = form.get("online_audit", ["off"])[0] == "on"
                    result, outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=out,
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=online_audit,
                        sarif=form.get("sarif", [""])[0],
                        cyclonedx=form.get("cyclonedx", [""])[0],
                        spdx=form.get("spdx", [""])[0],
                        html=form.get("html", [""])[0],
                    )
                    body = render_ui_page(scan_path, fail_on, result=result, outdir=outdir, notice="Scan completed.", ui_state=ui_state)
                elif self.path == "/explain":
                    rule = (form.get("rule", [""])[0] or "").strip().upper()
                    text = RULE_EXPLAINERS.get(rule)
                    if not text:
                        raise ValueError(f"Unknown finding rule: {rule}")
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                    body = render_ui_page(scan_path, fail_on, result=refreshed_result, outdir=refreshed_outdir, notice=f"{rule}: {text}", ui_state=ui_state)
                elif self.path == "/baseline":
                    report_rel = form.get("report", ["security-artifacts/safedeps-report.json"])[0] or "security-artifacts/safedeps-report.json"
                    output_rel = form.get("baseline_output", [".safedeps/vuln-baseline.json"])[0] or ".safedeps/vuln-baseline.json"
                    count = write_baseline_file(scan_path, report_rel, output_rel)
                    body = render_ui_page(scan_path, fail_on, notice=f"Baseline written: {scan_path / output_rel} ({count} entries)", ui_state=ui_state)
                elif self.path == "/approve":
                    updated, msg = upsert_approval_entry(
                        scan_path,
                        baseline_rel=form.get("baseline_file", [".safedeps/vuln-baseline.json"])[0] or ".safedeps/vuln-baseline.json",
                        manager=(form.get("manager", [""])[0] or "").strip(),
                        rule=(form.get("approve_rule", [""])[0] or "").strip().upper(),
                        package=(form.get("package", [""])[0] or "").strip(),
                        file_value=(form.get("file_value", [""])[0] or "").strip(),
                        expires=(form.get("expires", [""])[0] or "").strip(),
                    )
                    action = "Updated" if updated else "Added"
                    body = render_ui_page(scan_path, fail_on, notice=f"{action} approval: {msg}", ui_state=ui_state)
                elif self.path == "/setup":
                    cmd_setup(
                        argparse.Namespace(
                            path=str(scan_path),
                            fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                            force=True,
                        )
                    )
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                    body = render_ui_page(
                        scan_path,
                        fail_on,
                        result=refreshed_result,
                        outdir=refreshed_outdir,
                        notice="Project setup completed. Activate guard with: source .safedeps/activate.sh (bash) or . .safedeps/activate.ps1 (PowerShell)",
                        ui_state=ui_state,
                    )
                elif self.path == "/guard":
                    guard_action = (form.get("guard_action", [""])[0] or "").strip().lower()
                    notice_text = apply_guard_toggle(scan_path, guard_action)
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                    body = render_ui_page(scan_path, fail_on, result=refreshed_result, outdir=refreshed_outdir, notice=notice_text, ui_state=ui_state)
                elif self.path == "/deps":
                    notice_text = apply_dependency_action(
                        root=scan_path,
                        manager=(form.get("dep_manager", [""])[0] or "").strip().lower(),
                        action=(form.get("dep_action", [""])[0] or "").strip().lower(),
                        package=(form.get("dep_package", [""])[0] or "").strip(),
                        version=(form.get("dep_version", [""])[0] or "").strip(),
                        mode=(form.get("dep_mode", [""])[0] or "manual").strip().lower(),
                        approved=(form.get("dep_approved", ["off"])[0] == "on"),
                        approval_note="",
                    )
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                    body = render_ui_page(scan_path, fail_on, result=refreshed_result, outdir=refreshed_outdir, notice=notice_text, ui_state=ui_state)
                else:
                    if self.path == "/policy":
                        notice_text = apply_policy_quick_update(
                            scan_path,
                            action=(form.get("policy_action", [""])[0] or "").strip(),
                            manager=(form.get("policy_manager", [""])[0] or "").strip(),
                            package=(form.get("policy_package", [""])[0] or "").strip(),
                            registry=(form.get("policy_registry", [""])[0] or "").strip(),
                            policy_path=(form.get("policy_path", [""])[0] or "").strip(),
                        )
                        body = render_ui_page(scan_path, fail_on, notice=notice_text, ui_state=ui_state)
                    else:
                        action = (form.get("intel_action", ["save"])[0] or "save").strip().lower()
                        if action == "template":
                            create_intelligence_templates(scan_path)
                            ui_state = load_intelligence_into_state(ui_state, scan_path)
                            body = render_ui_page(scan_path, fail_on, notice="Intelligence templates created.", ui_state=ui_state)
                        else:
                            save_intelligence_from_state(scan_path, ui_state)
                            body = render_ui_page(scan_path, fail_on, notice="Intelligence files saved and validated.", ui_state=ui_state)
            except Exception as e:
                refreshed_result = None
                refreshed_outdir = None
                try:
                    refreshed_result, refreshed_outdir = run_scan_pipeline(
                        root=scan_path,
                        policy_arg=(form.get("policy", [""])[0] or None),
                        out=(form.get("out", ["security-artifacts"])[0] or "security-artifacts"),
                        fail_on=fail_on if fail_on in SEVERITY_ORDER else default_fail_on,
                        online_audit=False,
                        sarif="",
                        cyclonedx="",
                        spdx="",
                        html="",
                    )
                except Exception:
                    pass
                err_text = str(e)
                if self.path == "/deps":
                    err_text = _format_dependency_ui_error(err_text)
                body = render_ui_page(
                    scan_path,
                    fail_on,
                    result=refreshed_result,
                    outdir=refreshed_outdir,
                    error=err_text,
                    ui_state=ui_state,
                )
            self._send_html(body)

        def _send_html(self, body: str):
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer((host, port), UIHandler)
    url = f"http://{host}:{port}/"
    print(f"SafeDeps UI running at {url}")
    print("Press Ctrl+C to stop.")
    if args.open_browser:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0

def cmd_help(args):
    print("SafeDeps Quick Help")
    print("")
    print("Open UI")
    print("- PowerShell/CMD: safedeps ui . --host 127.0.0.1 --port 8877 --open-browser")
    print("- bash/zsh:       safedeps ui . --host 127.0.0.1 --port 8877 --open-browser")
    print("")
    print("Core Commands")
    print("- Scan:       safedeps scan . --fail-on HIGH")
    print("- Setup:      safedeps setup .")
    print("- Rule help:  safedeps explain FLOATING_VERSION")
    print("- Baseline:   safedeps baseline . --report security-artifacts/safedeps-report.json --output .safedeps/vuln-baseline.json")
    print("- Approval:   safedeps approve . --manager pip --rule UNPINNED_VERSION --package requests --expires 2026-12-31")
    print("")
    print("Guard Activation")
    print("- PowerShell: . .\\.safedeps\\activate.ps1")
    print("- bash/zsh:   source .safedeps/activate.sh")
    print("- Note: UI actions map to these command families (scan/setup/explain/baseline/approve/policy/deps).")
    print("")
    print("Expected Runtime Behavior")
    print("- Unpinned runtime installs (example: pip install colorama) are blocked.")
    print("- Pinned install example: pip install colorama==0.4.6")
    return 0

def render_ui_page(
    scan_path: Path,
    fail_on: str,
    result: ScanResult | None = None,
    outdir: Path | None = None,
    error: str = "",
    notice: str = "",
    ui_state: dict | None = None,
):
    state = ui_state or default_ui_state(scan_path, fail_on)
    state = load_intelligence_into_state(state, scan_path)
    setup_status = get_setup_status(scan_path)
    guard_status = get_guard_mode_status(scan_path)
    scope_mode = get_protection_scope(scan_path)
    auto_guard_enabled = _is_auto_guard_enabled(scan_path)
    deps_html = render_dependency_table(result, state["fail_on"], scan_path) if result is not None else "<p class='hint'>Run a scan to load dependencies and quick actions.</p>"
    shell_guard_status = get_current_shell_guard_status(scan_path)
    options = "".join(
        f"<option value=\"{s}\"{' selected' if s == state['fail_on'] else ''}>{s}</option>"
        for s in SEVERITY_ORDER.keys()
    )
    status_html = ""
    if error:
        status_html = f"<div class='error'>Scan error: {_html_escape(error)}</div>"
    elif notice:
        status_html = f"<div class='notice'>{_html_escape(notice)}</div>"
    elif result is not None:
        status_html = (
            f"<div class='status {'ok' if result.ok else 'fail'}'>"
            f"Status: {'PASS' if result.ok else 'FAIL'} | Findings: {len(result.findings)} | "
            f"Components: {len(result.sbom.get('components', []))} | Artifacts: {_html_escape(str(outdir or ''))}"
            "</div>"
        )
    checked = " checked" if state.get("online_audit") else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SafeDeps UI</title>
  <style>
    :root {{
      --bg:#eef3f9; --bg-2:#dfe7f4; --panel:#ffffff; --ink:#0f1f37; --muted:#52637a;
      --accent:#0f766e; --accent-2:#0b5f59; --danger:#b00020; --ok:#0c7a43; --border:#d6deea;
      --chip:#eef3fa; --shadow:0 12px 28px rgba(16,32,56,0.08);
      --hero-a:#f6f9ff; --hero-b:#e9f1ff; --hero-ink:#0f1f37;
    }}
    body[data-theme="dark"] {{
      --bg:#0f1623; --bg-2:#1a2537; --panel:#111b2b; --ink:#e8eef8; --muted:#9fb1cb;
      --accent:#2fb5a8; --accent-2:#239488; --danger:#ff6b7f; --ok:#33d18f; --border:#2b3b55;
      --chip:#1b2a3f; --shadow:0 10px 24px rgba(0,0,0,0.32);
      --hero-a:#0f243e; --hero-b:#17406b; --hero-ink:#f2f7ff;
    }}
    body {{ margin:0; font-family:"Segoe UI","Helvetica Neue",sans-serif; background:linear-gradient(120deg,var(--bg),var(--bg-2)); color:var(--ink); }}
    .wrap {{ max-width: 1200px; margin: 28px auto; padding: 0 16px; }}
    .panel {{ background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:20px; box-shadow:var(--shadow); }}
    h1 {{ margin:0 0 8px; }}
    h2 {{ margin:24px 0 10px; font-size:18px; }}
    .sub {{ margin:0 0 16px; color:var(--muted); }}
    form {{ display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-bottom: 16px; }}
    label {{ display:block; font-size:13px; margin-bottom:4px; }}
    input, select {{ width:100%; box-sizing:border-box; padding:10px; border:1px solid var(--border); border-radius:10px; background:var(--panel); color:var(--ink); }}
    textarea {{ width:100%; min-height:160px; box-sizing:border-box; padding:10px; border:1px solid var(--border); border-radius:10px; background:var(--panel); color:var(--ink); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .full {{ grid-column:1 / -1; }}
    .actions {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
    .quick-actions {{
      display:grid;
      grid-template-columns: repeat(3, minmax(120px, 1fr));
      gap:8px;
      align-items:stretch;
    }}
    .quick-actions > button,
    .quick-actions > .ghost,
    .quick-actions > .pick {{
      width:100%;
      min-height:32px;
      padding:6px 8px;
      font-size:12px;
      line-height:1.1;
      white-space:nowrap;
      overflow:hidden;
      text-overflow:ellipsis;
      text-align:center;
    }}
    .quick-actions .action-slot {{
      display:block;
      width:100%;
      min-height:32px;
    }}
    button {{ background:var(--accent); color:#fff; border:0; border-radius:10px; padding:10px 16px; font-weight:700; cursor:pointer; }}
    button:hover {{ background:var(--accent-2); }}
    .ghost {{ background:transparent; border:1px solid var(--border); color:var(--ink); }}
    .danger {{ background:var(--danger); }}
    .status {{ margin-top:16px; padding:12px; border-radius:10px; font-weight:600; border:1px solid var(--border); }}
    .status.ok {{ background:color-mix(in srgb, var(--ok) 16%, transparent); color:var(--ok); }}
    .status.fail {{ background:color-mix(in srgb, var(--danger) 16%, transparent); color:var(--danger); }}
    .notice {{ margin-top:16px; background:color-mix(in srgb, var(--accent) 14%, transparent); color:var(--ink); padding:12px; border-radius:10px; border:1px solid var(--border); }}
    .error {{ margin-top:16px; background:color-mix(in srgb, var(--danger) 16%, transparent); color:var(--danger); padding:12px; border-radius:10px; border:1px solid var(--border); }}
    .hint {{ margin-top:10px; font-size:12px; color:var(--muted); }}
    .pick {{ background:#2f5d8a; }}
    .chip {{ display:inline-block; padding:3px 8px; border-radius:999px; background:var(--chip); border:1px solid var(--border); font-size:12px; margin-right:6px; }}
    .toolbar {{ display:flex; justify-content:space-between; align-items:center; gap:10px; margin-bottom:14px; }}
    .hero {{
      border:0;
      border-radius:18px;
      padding:18px;
      background:linear-gradient(145deg, var(--hero-a), var(--hero-b));
      color:var(--hero-ink);
      margin-bottom:16px;
      box-shadow:0 16px 36px rgba(8,24,44,0.28);
    }}
    .hero-head {{ display:flex; justify-content:space-between; align-items:center; gap:12px; }}
    .hero-title {{ margin:0; font-size:24px; letter-spacing:.2px; }}
    .hero-sub {{ margin:4px 0 0; color:color-mix(in srgb, var(--hero-ink) 78%, transparent); }}
    .badge {{
      display:inline-flex; align-items:center; gap:8px;
      font-size:11px; text-transform:uppercase; font-weight:700; letter-spacing:.8px;
      padding:5px 10px; border-radius:999px;
      border:1px solid color-mix(in srgb, var(--hero-ink) 32%, transparent);
      color:var(--hero-ink); background:color-mix(in srgb, var(--hero-ink) 10%, transparent);
      margin-bottom:8px;
    }}
    .status-grid {{
      margin-top:12px;
      display:grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap:10px;
    }}
    .status-card {{
      border:1px solid color-mix(in srgb, var(--hero-ink) 26%, transparent);
      border-radius:12px;
      padding:10px;
      background:color-mix(in srgb, var(--hero-ink) 10%, transparent);
    }}
    .status-label {{ font-size:11px; text-transform:uppercase; letter-spacing:.6px; color:color-mix(in srgb, var(--hero-ink) 72%, transparent); }}
    .status-value {{ margin-top:4px; font-size:13px; font-weight:700; color:var(--hero-ink); }}
    .guard-bar {{
      margin-top:12px;
      border:1px solid color-mix(in srgb, var(--hero-ink) 26%, transparent);
      border-radius:12px;
      padding:10px;
      background:color-mix(in srgb, var(--hero-ink) 10%, transparent);
    }}
    .segmented {{
      display:inline-flex;
      border:1px solid color-mix(in srgb, var(--hero-ink) 30%, transparent);
      border-radius:999px;
      padding:2px;
      background:color-mix(in srgb, var(--hero-ink) 10%, transparent);
    }}
    .segmented button {{
      background:transparent;
      color:var(--hero-ink);
      border:0;
      border-radius:999px;
      padding:8px 12px;
      font-weight:700;
    }}
    .segmented button.active {{
      background:var(--hero-ink);
      color:var(--hero-a);
    }}
    .segmented.auto-toggle button.active.on {{
      background:var(--ok);
      color:#fff;
    }}
    .segmented.auto-toggle button.active.off {{
      background:var(--danger);
      color:#fff;
    }}
    .mini-actions {{ display:flex; gap:8px; flex-wrap:wrap; }}
    .mini-actions form {{ margin:0; }}
    .hero .ghost {{
      border:1px solid color-mix(in srgb, var(--hero-ink) 38%, transparent);
      color:var(--hero-ink);
      background:color-mix(in srgb, var(--hero-ink) 8%, transparent);
    }}
    .hero button {{
      background:color-mix(in srgb, #ffffff 16%, transparent);
      color:var(--hero-ink);
      border:1px solid color-mix(in srgb, var(--hero-ink) 34%, transparent);
    }}
    .hero button:hover {{
      background:color-mix(in srgb, #ffffff 24%, transparent);
    }}
    .hero .danger {{
      background:color-mix(in srgb, #b00020 50%, transparent);
      border-color:color-mix(in srgb, #ff8fa0 42%, transparent);
      color:#fff;
    }}
    .grid2 {{ display:grid; grid-template-columns: 1fr 1fr; gap:14px; }}
    .card {{ border:1px solid var(--border); border-radius:12px; padding:12px; background:var(--panel); }}
    .section {{
      margin-top:14px;
      border:1px solid var(--border);
      border-radius:14px;
      padding:14px;
      background:linear-gradient(180deg, color-mix(in srgb, var(--panel) 88%, var(--chip)), var(--panel));
      box-shadow:0 6px 16px rgba(16,32,56,0.06);
      position:relative;
      overflow:hidden;
    }}
    details.section > summary {{
      cursor:pointer;
      font-weight:700;
      color:var(--ink);
      list-style:none;
    }}
    details.section > summary::-webkit-details-marker {{ display:none; }}
    details.section > summary::before {{
      content:"▸";
      display:inline-block;
      margin-right:8px;
      transition:transform .2s ease;
      color:var(--muted);
    }}
    details.section[open] > summary::before {{ transform:rotate(90deg); }}
    .adv-tag {{
      font-size:11px;
      color:var(--muted);
      margin-left:6px;
      text-transform:uppercase;
      letter-spacing:.5px;
    }}
    .section h2 {{ margin-top:0; }}
    .section-loading {{
      pointer-events:none;
      opacity:.72;
    }}
    .section-loading::after {{
      content:"";
      position:absolute; inset:0;
      background:linear-gradient(90deg, transparent, rgba(255,255,255,0.32), transparent);
      animation: shimmer 1.1s infinite;
    }}
    body[data-theme="dark"] .section-loading::after {{
      background:linear-gradient(90deg, transparent, rgba(255,255,255,0.12), transparent);
    }}
    .modal-backdrop {{
      position:fixed; inset:0; z-index:9998;
      background:rgba(6,15,28,0.52);
      display:none; align-items:center; justify-content:center;
      padding:16px;
    }}
    .modal-backdrop.open {{ display:flex; }}
    .modal {{
      width:min(640px, 96vw);
      background:var(--panel);
      color:var(--ink);
      border:1px solid var(--border);
      border-radius:14px;
      box-shadow:0 22px 48px rgba(6,15,28,0.35);
      padding:16px;
    }}
    .modal-head {{
      display:flex; align-items:center; justify-content:space-between; gap:12px;
      margin-bottom:8px;
    }}
    .modal-title {{ margin:0; font-size:18px; }}
    .modal-close {{
      border:1px solid var(--border); background:transparent; color:var(--ink);
      width:32px; height:32px; border-radius:999px; padding:0; line-height:1;
      font-size:18px; cursor:pointer;
    }}
    .modal-body {{ color:var(--muted); line-height:1.45; }}
    .modal-body h4 {{ margin:10px 0 6px; color:var(--ink); font-size:14px; }}
    .modal-body p {{ margin:6px 0; }}
    .modal-body ul {{ margin:6px 0 8px 18px; padding:0; }}
    .modal-body li {{ margin:4px 0; }}
    .modal-code {{
      display:block; margin:6px 0; padding:8px 10px; border-radius:8px;
      background:var(--chip); border:1px solid var(--border); color:var(--ink);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      white-space:pre-wrap;
    }}
    .row-pending td {{ position:relative; overflow:hidden; color:transparent !important; }}
    .row-pending td::after {{
      content:"";
      position:absolute; inset:0;
      background:linear-gradient(90deg, transparent, rgba(255,255,255,0.35), transparent);
      animation: shimmer 1.1s infinite;
    }}
    body[data-theme="dark"] .row-pending td::after {{
      background:linear-gradient(90deg, transparent, rgba(255,255,255,0.12), transparent);
    }}
    .row-exit {{ opacity:0; transform:translateY(-6px); transition:opacity .28s ease, transform .28s ease; }}
    #deps-table-wrap tbody tr {{ transition: transform .28s cubic-bezier(.2,.8,.2,1), opacity .2s ease; will-change: transform; }}
    @keyframes shimmer {{
      0% {{ transform:translateX(-100%); }}
      100% {{ transform:translateX(100%); }}
    }}
    table {{ width:100%; border-collapse:collapse; margin-top:14px; }}
    th, td {{ border-bottom:1px solid var(--border); text-align:left; padding:8px; font-size:14px; vertical-align:top; }}
    th {{ background:var(--chip); }}
    @media (max-width: 900px) {{
      form, .grid2 {{ grid-template-columns: 1fr; }}
      .toolbar {{ flex-direction:column; align-items:flex-start; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="panel">
      <div class="hero" id="hero-wrap">
        <div class="hero-head">
          <div>
            <div class="badge">Runtime Guard Dashboard</div>
            <h1 class="hero-title">SafeDeps Control Center</h1>
            <p class="hero-sub">Security-first dependency workflow with guided actions, runtime guard, and policy control.</p>
          </div>
          <button id="theme-toggle" type="button" class="ghost" title="Switch between light and dark theme.">Theme</button>
        </div>
        <div class="status-grid">
          <div class="status-card">
            <div class="status-label">Setup</div>
            <div class="status-value" id="setup-status-line">{_html_escape(setup_status)}</div>
          </div>
          <div class="status-card">
            <div class="status-label">Auto Guard</div>
            <div class="status-value" id="autoguard-status-line">{_html_escape(guard_status)}</div>
          </div>
          <div class="status-card">
            <div class="status-label">Current Shell</div>
            <div class="status-value" id="shellguard-status-line">{_html_escape(shell_guard_status)}</div>
          </div>
        </div>
        <div class="guard-bar">
          <div class="toolbar" style="margin:0;">
            <div class="mini-actions">
              <form method="post" autocomplete="off" action="/setup" data-pending="hero-wrap">
                <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
                <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
                <button type="submit" title="Create or refresh SafeDeps wrappers and activation scripts for this project.">Setup Guard</button>
              </form>
              <form method="post" autocomplete="off" action="/guard" data-pending="hero-wrap">
                <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
                <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
                <div class="segmented auto-toggle" role="tablist" aria-label="Auto guard toggle">
                  <button type="submit" name="guard_action" value="enable_auto" class="{'active on' if auto_guard_enabled else ''}" title="Enable auto guard in future PowerShell sessions.">Auto ON</button>
                  <button type="submit" name="guard_action" value="disable_auto" class="{'active off' if not auto_guard_enabled else ''}" title="Disable auto guard in future PowerShell sessions.">Auto OFF</button>
                </div>
              </form>
            </div>
            <form method="post" autocomplete="off" action="/guard" data-pending="hero-wrap">
              <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
              <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
              <div class="segmented" role="tablist" aria-label="Protection scope">
                <button type="submit" name="guard_action" value="set_scope_project" class="{'active' if scope_mode == 'project' else ''}" title="Protect only this project context.">Project</button>
                <button type="submit" name="guard_action" value="set_scope_global" class="{'active' if scope_mode == 'global' else ''}" title="Protect commands globally in this shell profile context.">Global</button>
              </div>
            </form>
          </div>
        </div>
      </div>
      <div class="section" id="section-scan">
      <h2>1) Run Scan</h2>
      <form method="post" autocomplete="off" action="/scan" id="scan-form" data-ajax="1" data-pending="section-scan">
        <div class="full"><label title="Folder to scan.">Project path</label><input name="path" value="{_html_escape(state['path'])}" title="Absolute or relative path to the project root." /></div>
        <div><label title="Severity threshold that makes the scan fail.">Fail on</label><select name="fail_on" title="Findings at or above this level mark the scan as failed.">{options}</select></div>
        <div><label title="Where reports and artifacts are written.">Output dir</label><input name="out" value="{_html_escape(state['out'])}" title="Output directory for scan artifacts." /></div>
        <div><label title="Optional custom policy file.">Policy file (optional)</label><input name="policy" value="{_html_escape(state['policy'])}" placeholder=".safedeps/policy.json" title="Leave empty to use default policy." /></div>
        <div><label>SARIF path (optional)</label><input name="sarif" value="{_html_escape(state['sarif'])}" placeholder="security-artifacts/safedeps.sarif" /></div>
        <div><label>CycloneDX path (optional)</label><input name="cyclonedx" value="{_html_escape(state['cyclonedx'])}" placeholder="security-artifacts/safedeps.cdx.json" /></div>
        <div><label>SPDX path (optional)</label><input name="spdx" value="{_html_escape(state['spdx'])}" placeholder="security-artifacts/safedeps.spdx.json" /></div>
        <div><label>HTML path (optional)</label><input name="html" value="{_html_escape(state['html'])}" placeholder="security-artifacts/safedeps-report.html" /></div>
        <div class="full actions">
          <label title="Enable extra network-based checks if available."><input type="checkbox" name="online_audit"{checked}> Online audit</label>
          <button type="submit" title="Run scan again with current settings and refresh all sections.">Re-Scan</button>
        </div>
      </form>
      </div>
      <div class="section" id="section-deps-view">
      <h2>2) Dependency View And Quick Actions</h2>
      <div class="card" id="deps-table-wrap">
        <p class="sub">This section becomes interactive after a scan. Use it to quickly trust registries, deny packages, and create approvals with expiration.</p>
        {deps_html}
      </div>
      <div id="status-wrap">{status_html}</div>
      <div id="pip-guard-wrap">{render_pip_guard_panel(result, state["fail_on"]) if result is not None else ""}</div>
      <details class="card" style="margin-top:12px;">
        <summary style="cursor:pointer; font-weight:700;" title="Detailed findings list used for temporary exception workflows.">Advanced Findings (for manual approvals)</summary>
        <div id="findings-wrap">{render_findings_table(result) if result is not None else ""}</div>
      </details>
      </div>
      <div class="section" id="section-deps-manage">
      <h2>3) Manage Dependencies (Guided)</h2>
      <p class="sub">Use this area if you want SafeDeps to execute package changes for you. Example: install `colorama` with version `0.4.6`, or run `Safe Update` for one package only.</p>
      <form method="post" autocomplete="off" action="/deps" id="deps-form" data-ajax="1" data-pending="section-deps-manage">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div><label title="Package manager to execute action with.">Manager</label>
          <select name="dep_manager" id="dep-manager">
            <option value="pip">pip</option>
            <option value="npm">npm</option>
          </select>
        </div>
        <div><label title="Install, update, or uninstall a package.">Action</label>
          <select name="dep_action" id="dep-action">
            <option value="install">Install</option>
            <option value="update">Update</option>
            <option value="uninstall">Uninstall</option>
          </select>
        </div>
        <div><label title="Package name only (no extra flags).">Package</label><input name="dep_package" id="dep-package" value="" placeholder="colorama / lodash" title="Example: colorama (pip) or lodash (npm)." /></div>
        <div><label title="Exact version for manual mode.">Version (required for manual install/update)</label><input name="dep_version" id="dep-version" value="" placeholder="0.4.6 / 4.17.21" title="Use exact versions in manual mode." /></div>
        <div><label title="Manual requires exact version; Auto tries safe latest.">Mode</label>
          <select name="dep_mode" id="dep-mode">
            <option value="manual">Manual (exact version)</option>
            <option value="auto">Auto (safe latest via manager)</option>
          </select>
        </div>
        <div class="full actions">
          <label><input type="checkbox" name="dep_approved" id="dep-approved"> I understand the risk and approve this dependency change</label>
        </div>
        <div class="full hint">Safety: install/update runs a pre-check scan and blocks if CRITICAL findings are present. If package trust is uncertain, explicit approval is required.</div>
        <div class="full actions"><button type="submit" title="Execute dependency operation with SafeDeps checks.">Apply Dependency Action</button></div>
      </form>
      </div>
      <details class="section" id="section-rule-help">
      <summary>4) Explain Scan Warnings/Errors <span class="adv-tag">(Advanced)</span></summary>
      <p class="sub">Use this when SafeDeps shows a warning/error code and you do not understand it. Enter the exact code from findings (example: `FLOATING_VERSION`, `UNPINNED_VERSION`, `MISSING_LOCKFILE`).</p>
      <form method="post" autocomplete="off" action="/explain" data-ajax="1" data-pending="section-rule-help">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div><label title="Code shown in SafeDeps findings table.">Warning/error code</label><input name="rule" value="{_html_escape(state['rule'])}" placeholder="FLOATING_VERSION" title="Enter the exact code you see in findings, for example UNPINNED_VERSION." /></div>
        <div class="actions"><button type="submit">Explain Rule</button></div>
      </form>
      </details>
      <details class="section" id="section-baseline">
      <summary>5) Baseline And Exceptions <span class="adv-tag">(Advanced)</span></summary>
      <p class="sub">Use baseline only for controlled exceptions. Always set expiration dates.</p>
      <form method="post" autocomplete="off" action="/baseline" data-ajax="1" data-pending="section-baseline">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div><label title="Scan report JSON used to build baseline.">Report path</label><input name="report" value="{_html_escape(state['report'])}" title="Path to safedeps-report.json." /></div>
        <div><label>Baseline output path</label><input name="baseline_output" value="{_html_escape(state['baseline_output'])}" /></div>
        <div class="full actions"><button type="submit">Create Baseline</button></div>
      </form>
      <form method="post" autocomplete="off" action="/approve" id="approve-form" data-ajax="1" data-pending="section-baseline">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div><label>Baseline file</label><input id="approve-baseline-file" name="baseline_file" value="{_html_escape(state['baseline_file'])}" /></div>
        <div><label>Manager</label><input id="approve-manager" name="manager" value="{_html_escape(state['manager'])}" placeholder="npm / pip / nuget" /></div>
        <div><label>Rule</label><input id="approve-rule" name="approve_rule" value="{_html_escape(state['approve_rule'])}" placeholder="FLOATING_VERSION" /></div>
        <div><label>Package (optional)</label><input id="approve-package" name="package" value="{_html_escape(state['package'])}" placeholder="lodash" /></div>
        <div><label>File (optional)</label><input id="approve-file" name="file_value" value="{_html_escape(state['file_value'])}" placeholder="package.json" /></div>
        <div><label>Expires (YYYY-MM-DD)</label><input id="approve-expires" name="expires" value="{_html_escape(state['expires'])}" placeholder="2026-12-31" /></div>
        <div class="full actions"><button type="submit">Add/Update Approval</button></div>
        <div class="full hint">Tip: use "Use For Approval" on a finding row to prefill manager/rule/package/file.</div>
      </form>
      </details>
      <details class="section" id="section-policy">
      <summary>6) Policy Quick Editor <span class="adv-tag">(Advanced)</span></summary>
      <p class="sub">This section is for custom hardening. Most users can keep defaults and only use scan + guided dependency actions.</p>
      <div class="grid2">
        <form method="post" autocomplete="off" action="/policy" data-ajax="1" data-pending="section-policy">
          <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
          <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
          <input type="hidden" name="policy_action" value="add_registry" />
          <div><label>Policy file (optional)</label><input name="policy_path" value="{_html_escape(state['policy'])}" placeholder=".safedeps/policy.json" /></div>
          <div><label>Manager</label><input name="policy_manager" value="" placeholder="npm / pip / nuget" /></div>
          <div class="full"><label>Registry URL to trust</label><input name="policy_registry" value="" placeholder="https://registry.npmjs.org/" /></div>
          <div class="full actions"><button type="submit">Add Registry To Allowlist</button></div>
        </form>
        <form method="post" autocomplete="off" action="/policy" data-ajax="1" data-pending="section-policy">
          <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
          <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
          <div><label>Policy action</label>
            <select name="policy_action">
              <option value="add_deny">Add deny package</option>
              <option value="remove_deny">Remove deny package</option>
            </select>
          </div>
          <div><label>Package name</label><input name="policy_package" value="" placeholder="example-package" /></div>
          <div class="full"><label>Policy file (optional)</label><input name="policy_path" value="{_html_escape(state['policy'])}" placeholder=".safedeps/policy.json" /></div>
          <div class="full actions"><button type="submit">Apply Package Policy Action</button></div>
        </form>
      </div>
      </details>
      <details class="section" id="section-intel">
      <summary>7) Intelligence Settings <span class="adv-tag">(Advanced)</span></summary>
      <form method="post" autocomplete="off" action="/intelligence" data-ajax="1" data-pending="section-intel">
        <div class="full"><label>Intelligence Settings</label></div>
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div class="full"><label>Local vulnerability feed JSON (`.safedeps/vuln-feed.json`)</label><textarea name="vuln_feed_json">{_html_escape(state['vuln_feed_json'])}</textarea></div>
        <div class="full"><label>Local metadata cache JSON (`.safedeps/metadata-cache.json`)</label><textarea name="metadata_cache_json">{_html_escape(state['metadata_cache_json'])}</textarea></div>
        <div class="full actions">
          <button type="submit" name="intel_action" value="save">Save Intelligence Files</button>
          <button type="submit" name="intel_action" value="template">Create Starter Templates</button>
        </div>
        <div class="full hint">This lets users configure local intelligence visually instead of editing files manually.</div>
      </form>
      </details>
    </div>
  </div>
  <div class="modal-backdrop" id="rule-modal-backdrop" aria-hidden="true">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="rule-modal-title">
      <div class="modal-head">
        <h3 class="modal-title" id="rule-modal-title">Rule Explanation</h3>
        <button type="button" class="modal-close" id="rule-modal-close" aria-label="Close">×</button>
      </div>
      <div class="modal-body" id="rule-modal-body"></div>
    </div>
  </div>
  <div class="modal-backdrop" id="dep-approve-modal-backdrop" aria-hidden="true">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="dep-approve-modal-title">
      <div class="modal-head">
        <h3 class="modal-title" id="dep-approve-modal-title">Approval required for Safe Update</h3>
        <button type="button" class="modal-close" id="dep-approve-modal-close" aria-label="Close">×</button>
      </div>
      <div class="modal-body">
        <p id="dep-approve-modal-text">This action may require explicit approval.</p>
        <div class="actions" style="margin-top:10px;">
          <button type="button" id="dep-approve-confirm">Confirm update</button>
          <button type="button" class="ghost" id="dep-approve-cancel">Cancel</button>
        </div>
      </div>
    </div>
  </div>
  <script>
    (function() {{
      const saved = localStorage.getItem("safedeps-theme");
      if (saved) document.body.setAttribute("data-theme", saved);
      const btn = document.getElementById("theme-toggle");
      if (btn) {{
        btn.addEventListener("click", function() {{
          const current = document.body.getAttribute("data-theme") === "dark" ? "dark" : "light";
          const next = current === "dark" ? "light" : "dark";
          document.body.setAttribute("data-theme", next);
          localStorage.setItem("safedeps-theme", next);
        }});
      }}
    }})();
    function setApprovalFields(manager, rule, pkg, filePath) {{
      const m = document.getElementById("approve-manager");
      const r = document.getElementById("approve-rule");
      const p = document.getElementById("approve-package");
      const f = document.getElementById("approve-file");
      if (m) m.value = manager || "";
      if (r) r.value = rule || "";
      if (p) p.value = pkg || "";
      if (f) f.value = filePath || "";
      const form = document.getElementById("approve-form");
      if (form) form.scrollIntoView({{ behavior: "smooth", block: "center" }});
    }}
    function quickApprove(manager, rule, pkg, filePath) {{
      setApprovalFields(manager, rule, pkg, filePath);
      const exp = document.getElementById("approve-expires");
      if (exp && !exp.value) {{
        const dt = new Date();
        dt.setDate(dt.getDate() + 30);
        const yyyy = dt.getFullYear();
        const mm = String(dt.getMonth() + 1).padStart(2, "0");
        const dd = String(dt.getDate()).padStart(2, "0");
        exp.value = `${{yyyy}}-${{mm}}-${{dd}}`;
      }}
    }}
    function prepareDependencyAction(manager, action, pkg, version, mode) {{
      const m = document.getElementById("dep-manager");
      const a = document.getElementById("dep-action");
      const p = document.getElementById("dep-package");
      const v = document.getElementById("dep-version");
      const md = document.getElementById("dep-mode");
      const ap = document.getElementById("dep-approved");
      if (m) m.value = manager || "pip";
      if (a) a.value = action || "install";
      if (p) p.value = pkg || "";
      if (v) v.value = version || "";
      if (md) md.value = mode || "manual";
      if (ap) ap.checked = false;
      const form = document.getElementById("deps-form");
      if (form) form.scrollIntoView({{ behavior: "smooth", block: "center" }});
    }}
    let depApprovalContext = null;
    function openDepApprovalModal(ctx) {{
      depApprovalContext = ctx;
      const backdrop = document.getElementById("dep-approve-modal-backdrop");
      const txt = document.getElementById("dep-approve-modal-text");
      if (txt) {{
        txt.textContent = "Safe Update checks package trust signals. If metadata is missing or risky, approval is required. Confirm only if you reviewed the package and accept the risk.";
      }}
      if (backdrop) {{
        backdrop.classList.add("open");
        backdrop.setAttribute("aria-hidden", "false");
      }}
    }}
    function closeDepApprovalModal() {{
      const backdrop = document.getElementById("dep-approve-modal-backdrop");
      if (!backdrop) return;
      backdrop.classList.remove("open");
      backdrop.setAttribute("aria-hidden", "true");
      depApprovalContext = null;
    }}
    async function confirmDepApprovalAndRun() {{
      if (!depApprovalContext) return;
      const m = document.getElementById("dep-manager");
      const a = document.getElementById("dep-action");
      const p = document.getElementById("dep-package");
      const v = document.getElementById("dep-version");
      const md = document.getElementById("dep-mode");
      const ap = document.getElementById("dep-approved");
      if (m) m.value = depApprovalContext.manager || "pip";
      if (a) a.value = depApprovalContext.action || "update";
      if (p) p.value = depApprovalContext.pkg || "";
      if (v) v.value = "";
      if (md) md.value = depApprovalContext.mode || "auto";
      if (ap) ap.checked = true;
      const row = depApprovalContext.row || null;
      closeDepApprovalModal();
      await submitFormAjax("deps-form", row, false);
    }}
    function executeDependencyAction(manager, action, pkg, mode) {{
      const m = document.getElementById("dep-manager");
      const a = document.getElementById("dep-action");
      const p = document.getElementById("dep-package");
      const v = document.getElementById("dep-version");
      const md = document.getElementById("dep-mode");
      const ap = document.getElementById("dep-approved");
      if (m) m.value = manager || "pip";
      if (a) a.value = action || "update";
      if (p) p.value = pkg || "";
      if (v) v.value = "";
      if (md) md.value = mode || "auto";
      if (ap) ap.checked = false;
      const row = document.querySelector(`tr[data-manager="${{manager.toLowerCase()}}"][data-package="${{pkg.toLowerCase()}}"]`);
      if (action === "update" && (mode || "").toLowerCase() === "auto") {{
        openDepApprovalModal({{ manager, action, pkg, mode, row }});
        return;
      }}
      const ok = confirm(`Proceed with ${{action}} for ${{pkg}} using ${{manager}}?`);
      if (!ok) return;
      submitFormAjax("deps-form", row, action === "uninstall");
    }}
    function bindAjaxHandlers() {{
      document.querySelectorAll('form[data-ajax="1"], .hero form[method="post"]').forEach(form => {{
        if (form.dataset.ajaxBound === "1") return;
        form.dataset.ajaxBound = "1";
        form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(btn => {{
          btn.addEventListener("click", function() {{
            form.__lastSubmitter = btn;
          }});
        }});
        form.addEventListener("submit", function(ev) {{
          ev.preventDefault();
          const isScan = form.id === "scan-form";
          submitFormAjax(form, null, false, isScan, ev.submitter || form.__lastSubmitter || null).then(() => {{
            if (form.action && form.action.endsWith("/explain")) {{
              const st = document.getElementById("status-wrap");
              if (st) {{
                const txt = (st.textContent || "").trim();
                if (txt) openRuleModal(txt);
              }}
            }}
          }});
        }});
      }});
    }}
    function escapeHtml(s) {{
      return String(s || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }}
    function openRuleModal(messageText) {{
      const backdrop = document.getElementById("rule-modal-backdrop");
      const body = document.getElementById("rule-modal-body");
      if (!backdrop || !body) return;
      let pretty = messageText || "";
      if (pretty.includes(":")) {{
        const idx = pretty.indexOf(":");
        const code = pretty.slice(0, idx).trim();
        const msg = pretty.slice(idx + 1).trim();
        let nextHtml = "<p>Pin exact versions and use a lockfile.</p>";
        if (code === "FLOATING_VERSION" || code === "UNPINNED_VERSION") {{
          nextHtml =
            "<ul>" +
            "<li>Use an exact version, not a range.</li>" +
            "<li>Example (pip): <span class='modal-code'>requests==2.32.3</span> (not <span class='modal-code'>requests>=2</span>).</li>" +
            "<li>Create/update a lockfile and commit it to Git.</li>" +
            "</ul>";
        }} else if (code === "MISSING_LOCKFILE") {{
          nextHtml =
            "<ul>" +
            "<li>pip/requirements: <span class='modal-code'>pip freeze > requirements.lock</span></li>" +
            "<li>poetry: <span class='modal-code'>poetry lock</span></li>" +
            "<li>npm: <span class='modal-code'>npm install</span> (creates <span class='modal-code'>package-lock.json</span>), then use <span class='modal-code'>npm ci</span></li>" +
            "<li>nuget: enable <span class='modal-code'>RestorePackagesWithLockFile</span> and commit <span class='modal-code'>packages.lock.json</span></li>" +
            "</ul>";
        }}
        body.innerHTML =
          `<h4>Rule</h4><p><strong>${{escapeHtml(code)}}</strong></p>` +
          `<h4>What this means</h4><p>${{escapeHtml(msg)}}</p>` +
          "<h4>Why this matters</h4><p>Without pinned versions/lockfiles, two developers may install different dependency trees and one may pull a risky version.</p>" +
          "<h4>What to do next</h4>" +
          nextHtml;
      }} else {{
        body.innerHTML = `<p>${{escapeHtml(pretty)}}</p>`;
      }}
      backdrop.classList.add("open");
      backdrop.setAttribute("aria-hidden", "false");
    }}
    function closeRuleModal() {{
      const backdrop = document.getElementById("rule-modal-backdrop");
      if (!backdrop) return;
      backdrop.classList.remove("open");
      backdrop.setAttribute("aria-hidden", "true");
    }}
    (function wireRuleModal() {{
      const backdrop = document.getElementById("rule-modal-backdrop");
      const closeBtn = document.getElementById("rule-modal-close");
      if (closeBtn) closeBtn.addEventListener("click", closeRuleModal);
      if (backdrop) {{
        backdrop.addEventListener("click", function(ev) {{
          if (ev.target === backdrop) closeRuleModal();
        }});
      }}
      document.addEventListener("keydown", function(ev) {{
        if (ev.key === "Escape") closeRuleModal();
      }});
    }})();
    (function wireDepApproveModal() {{
      const backdrop = document.getElementById("dep-approve-modal-backdrop");
      const closeBtn = document.getElementById("dep-approve-modal-close");
      const cancelBtn = document.getElementById("dep-approve-cancel");
      const confirmBtn = document.getElementById("dep-approve-confirm");
      if (closeBtn) closeBtn.addEventListener("click", closeDepApprovalModal);
      if (cancelBtn) cancelBtn.addEventListener("click", closeDepApprovalModal);
      if (confirmBtn) confirmBtn.addEventListener("click", confirmDepApprovalAndRun);
      if (backdrop) {{
        backdrop.addEventListener("click", function(ev) {{
          if (ev.target === backdrop) closeDepApprovalModal();
        }});
      }}
    }})();
    function parseAndSwapSections(htmlText) {{
      const parser = new DOMParser();
      const doc = parser.parseFromString(htmlText, "text/html");
      const prevRows = new Map();
      document.querySelectorAll("#deps-table-wrap tbody tr[data-manager][data-package]").forEach(tr => {{
        const k = `${{tr.dataset.manager}}|${{tr.dataset.package}}`;
        prevRows.set(k, tr.getBoundingClientRect());
      }});
      const ids = [
        "hero-wrap", "section-scan", "section-deps-view", "section-deps-manage",
        "section-rule-help", "section-baseline", "section-policy", "section-intel",
        "deps-table-wrap", "status-wrap", "pip-guard-wrap", "findings-wrap",
        "setup-status-line", "autoguard-status-line", "shellguard-status-line"
      ];
      ids.forEach(id => {{
        const src = doc.getElementById(id);
        const dst = document.getElementById(id);
        if (src && dst) {{
          dst.innerHTML = src.innerHTML;
        }}
      }});
      const newRows = new Map();
      document.querySelectorAll("#deps-table-wrap tbody tr[data-manager][data-package]").forEach(tr => {{
        const k = `${{tr.dataset.manager}}|${{tr.dataset.package}}`;
        newRows.set(k, tr);
      }});
      newRows.forEach((tr, k) => {{
        const prev = prevRows.get(k);
        if (!prev) return;
        const now = tr.getBoundingClientRect();
        const dy = prev.top - now.top;
        if (Math.abs(dy) > 0.5) {{
          tr.style.transform = `translateY(${{dy}}px)`;
          requestAnimationFrame(() => {{
            tr.style.transform = "translateY(0)";
          }});
        }}
      }});
      bindAjaxHandlers();
    }}
    async function submitFormAjax(formRef, rowEl, animateExit, fullTablePending, submitter) {{
      const form = typeof formRef === "string" ? document.getElementById(formRef) : formRef;
      if (!form) return;
      const pendingId = form.getAttribute("data-pending");
      const pendingEl = pendingId ? document.getElementById(pendingId) : null;
      if (pendingEl) pendingEl.classList.add("section-loading");
      if (rowEl) rowEl.classList.add("row-pending");
      if (fullTablePending) {{
        document.querySelectorAll("#deps-table-wrap tbody tr").forEach(tr => tr.classList.add("row-pending"));
      }}
      try {{
        const fd = new FormData(form);
        const btn = submitter || form.__lastSubmitter;
        if (btn && btn.name) {{
          fd.append(btn.name, btn.value || "");
        }}
        const body = new URLSearchParams(fd);
        const res = await fetch(form.action, {{
          method: "POST",
          headers: {{ "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8" }},
          body
        }});
        const text = await res.text();
        if (rowEl && animateExit) {{
          rowEl.classList.remove("row-pending");
          rowEl.classList.add("row-exit");
          await new Promise(r => setTimeout(r, 280));
        }}
        parseAndSwapSections(text);
      }} finally {{
        if (pendingEl) pendingEl.classList.remove("section-loading");
        if (fullTablePending) {{
          document.querySelectorAll("#deps-table-wrap tbody tr").forEach(tr => tr.classList.remove("row-pending"));
        }}
      }}
    }}
    bindAjaxHandlers();
  </script>
</body>
</html>
"""

def render_findings_table(result: ScanResult):
    if not result.findings:
        return "<p>No findings.</p>"
    rows = []
    for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0), reverse=True):
        rows.append(
            "<tr>"
            f"<td>{_html_escape(f.severity)}</td>"
            f"<td>{_html_escape(f.manager)}</td>"
            f"<td>{_html_escape(f.rule)}</td>"
            f"<td>{_html_escape(f.package)}</td>"
            f"<td>{_html_escape(f.file)}</td>"
            f"<td>{_html_escape(f.message)}</td>"
            f"<td><button class='pick' type='button' onclick=\"setApprovalFields('{_js_escape(f.manager)}','{_js_escape(f.rule)}','{_js_escape(f.package)}','{_js_escape(f.file)}')\">Use For Approval</button></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Severity</th><th>Manager</th><th>Rule</th><th>Package</th><th>File</th><th>Message</th><th>Action</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )

def render_dependency_table(result: ScanResult, fail_on: str, root: Path):
    comps = _unique_components(result.sbom.get("components", []))
    runtime = collect_runtime_components(root)
    if runtime:
        comps.extend(runtime)
        comps = _unique_components(comps)
    if not comps:
        return "<p class='hint'>No dependencies detected in the current scan.</p>"

    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["HIGH"])
    by_pkg = {}
    for c in comps:
        manager = str(c.get("manager", "")).strip()
        name = str(c.get("name", "")).strip()
        if not manager or not name:
            continue
        key = (manager.lower(), name.lower())
        if key not in by_pkg:
            by_pkg[key] = {
                "manager": manager,
                "name": name,
                "version": str(c.get("version", "")).strip(),
                "findings": [],
            }
        elif not by_pkg[key]["version"]:
            by_pkg[key]["version"] = str(c.get("version", "")).strip()

    for f in result.findings:
        if not f.package:
            continue
        key = (str(f.manager or "").lower(), str(f.package or "").lower())
        if key not in by_pkg:
            by_pkg[key] = {
                "manager": str(f.manager or "").strip() or "unknown",
                "name": str(f.package or "").strip(),
                "version": "",
                "findings": [],
            }
        by_pkg[key]["findings"].append(f)

    rows = []
    for dep in sorted(by_pkg.values(), key=lambda x: (x["manager"].lower(), x["name"].lower())):
        findings = dep["findings"]
        worst = "OK"
        if findings:
            worst = max(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 0)).severity
        status = "Blocked" if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold and f.severity != "INFO" for f in findings) else "Installed"
        if not findings:
            status = "Approved/Installed"
        rules = ", ".join(sorted({f.rule for f in findings})) if findings else "-"
        primary = findings[0] if findings else None
        quick = ""
        if primary:
            approve_btn = (
                f"<button class='pick' type='button' "
                f"onclick=\"quickApprove('{_js_escape(primary.manager)}','{_js_escape(primary.rule)}','{_js_escape(primary.package)}','{_js_escape(primary.file)}')\">"
                "Approve (+30 days)</button>"
            )
            uninstall_btn = (
                f"<button class='ghost' type='button' "
                f"onclick=\"executeDependencyAction('{_js_escape(dep['manager'])}','uninstall','{_js_escape(dep['name'])}','manual')\">"
                "Uninstall</button>"
            )
            safe_update_btn = (
                f"<button type='button' "
                f"onclick=\"executeDependencyAction('{_js_escape(dep['manager'])}','update','{_js_escape(dep['name'])}','auto')\">"
                "Safe Update</button>"
            )
            quick = f"<div class='quick-actions'>{approve_btn}{uninstall_btn}{safe_update_btn}</div>"
        else:
            uninstall_btn = (
                f"<button class='ghost' type='button' "
                f"onclick=\"executeDependencyAction('{_js_escape(dep['manager'])}','uninstall','{_js_escape(dep['name'])}','manual')\">"
                "Uninstall</button>"
            )
            safe_update_btn = (
                f"<button type='button' "
                f"onclick=\"executeDependencyAction('{_js_escape(dep['manager'])}','update','{_js_escape(dep['name'])}','auto')\">"
                "Safe Update</button>"
            )
            quick = f"<div class='quick-actions'><span class='action-slot' aria-hidden='true'></span>{uninstall_btn}{safe_update_btn}</div>"
        rows.append(
            f"<tr data-manager=\"{_html_escape(dep['manager'].lower())}\" data-package=\"{_html_escape(dep['name'].lower())}\">"
            f"<td>{_html_escape(dep['manager'])}</td>"
            f"<td>{_html_escape(dep['name'])}</td>"
            f"<td>{_html_escape(dep['version'] or '(unresolved)')}</td>"
            f"<td>{_html_escape(worst)}</td>"
            f"<td>{_html_escape(status)}</td>"
            f"<td>{_html_escape(rules)}</td>"
            f"<td>{quick}</td>"
            "</tr>"
        )

    return (
        "<table><thead><tr>"
        "<th>Manager</th><th>Package</th><th>Version</th><th>Worst Severity</th><th>Status</th><th>Rules</th><th>Quick Action</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )

def collect_runtime_components(root: Path):
    out = []
    # Python runtime packages from current interpreter environment.
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format", "json"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout or "[]")
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name", "")).strip()
                    ver = str(item.get("version", "")).strip()
                    if name:
                        out.append({"type": "library", "manager": "pip", "name": name, "version": ver, "scope": "runtime:pip"})
    except Exception:
        pass

    # npm runtime packages if a Node project exists.
    try:
        if (root / "package.json").exists():
            proc = subprocess.run(
                ["npm", "ls", "--depth=0", "--json"],
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0:
                data = json.loads(proc.stdout or "{}")
                deps = data.get("dependencies", {}) if isinstance(data, dict) else {}
                if isinstance(deps, dict):
                    for name, meta in deps.items():
                        if not isinstance(name, str):
                            continue
                        ver = ""
                        if isinstance(meta, dict):
                            ver = str(meta.get("version", "")).strip()
                        out.append({"type": "library", "manager": "npm", "name": name.strip(), "version": ver, "scope": "runtime:npm"})
    except Exception:
        pass

    return out

def render_pip_guard_panel(result: ScanResult, fail_on: str):
    threshold = SEVERITY_ORDER.get(fail_on, SEVERITY_ORDER["HIGH"])
    pip_blockers = [
        f for f in result.findings
        if f.manager == "pip" and f.severity != "INFO" and SEVERITY_ORDER.get(f.severity, 0) >= threshold
    ]
    if not pip_blockers:
        return (
            "<div class='notice'>"
            f"Pip install guard: no blocking pip findings at threshold {fail_on}."
            "</div>"
        )
    items = "".join(
        f"<li>{_html_escape(f.package or '(unknown)')} - {_html_escape(f.rule)} - {_html_escape(f.message)}</li>"
        for f in pip_blockers
    )
    return (
        "<div class='error'>"
        f"Pip install guard: {len(pip_blockers)} blocking finding(s) at threshold {fail_on}."
        f"<ul>{items}</ul>"
        "</div>"
    )

def apply_policy_quick_update(root: Path, action: str, manager: str, package: str, registry: str, policy_path: str):
    action = (action or "").strip().lower()
    manager = (manager or "").strip().lower()
    package = (package or "").strip()
    registry = (registry or "").strip()

    if policy_path:
        p = Path(policy_path)
        policy_file = p if p.is_absolute() else (root / p)
    else:
        policy_file = root / ".safedeps" / "policy.json"

    policy_file.parent.mkdir(parents=True, exist_ok=True)
    if policy_file.exists():
        try:
            data = json.loads(policy_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid policy JSON: {e}") from e
    else:
        data = json.loads(json.dumps(DEFAULT_POLICY))

    if action == "add_registry":
        if not manager:
            raise ValueError("manager is required for add_registry")
        if not registry:
            raise ValueError("registry URL is required for add_registry")
        allowed = data.setdefault("allowed_registries", {})
        entries = allowed.setdefault(manager, [])
        if registry not in entries:
            entries.append(registry)
            msg = f"Added registry to allowlist: {manager} -> {registry}"
        else:
            msg = f"Registry already present: {manager} -> {registry}"
    elif action == "add_deny":
        if not package:
            raise ValueError("package is required for add_deny")
        deny = data.setdefault("deny_packages", [])
        if package not in deny:
            deny.append(package)
            msg = f"Added deny package: {package}"
        else:
            msg = f"Package already in denylist: {package}"
    elif action == "remove_deny":
        if not package:
            raise ValueError("package is required for remove_deny")
        deny = data.setdefault("deny_packages", [])
        new_deny = [x for x in deny if str(x).lower() != package.lower()]
        if len(new_deny) == len(deny):
            msg = f"Package not found in denylist: {package}"
        else:
            data["deny_packages"] = new_deny
            msg = f"Removed deny package: {package}"
    else:
        raise ValueError(f"Unknown policy action: {action}")

    policy_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return f"{msg} (saved to {policy_file})"

def _is_valid_package_name(name: str):
    if not name:
        return False
    for ch in name:
        if ch.isalnum() or ch in "._-@/":
            continue
        return False
    return True

def _is_exact_version(ver: str):
    if not ver:
        return False
    for bad in ("^", "~", "*", ">", "<", "=", "latest", "x"):
        if bad in ver.lower():
            return False
    return True

def _run_cmd(args: list[str], cwd: Path):
    proc = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True)
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    text = out if out else err
    return proc.returncode, text

def _format_dependency_ui_error(raw: str):
    text = str(raw or "").strip()
    if "Explicit approval required before this dependency change." in text:
        return (
            "Update blocked for safety. We could not verify trusted metadata for this package yet. "
            "If you still want to continue, confirm approval from the Safe Update overlay or tick the approval checkbox in 'Manage Dependencies'. "
            "For long-term use, fill '.safedeps/metadata-cache.json' in Intelligence Settings."
        )
    if "Manual install/update requires an exact version" in text:
        return "Blocked: you must use an exact version (example: 1.2.3). Do not use ranges like >=, ^ or latest."
    if "Blocked by CRITICAL findings" in text:
        return "Blocked: there are CRITICAL findings in this project. Resolve those first, then retry this action."
    if "failed compatibility checks and was rolled back" in text:
        return "Update blocked: compatibility checks failed, so SafeDeps restored the previous version automatically."
    return text

def _safe_auto_version_pip(root: Path, package: str):
    code, text = _run_cmd([sys.executable, "-m", "pip", "index", "versions", package], root)
    if code != 0:
        raise ValueError(f"pip index versions failed for {package}: {text}")
    line = ""
    for ln in text.splitlines():
        if "Available versions:" in ln:
            line = ln
            break
    if not line:
        raise ValueError(f"Could not resolve available versions for {package}.")
    versions = [x.strip() for x in line.split(":", 1)[1].split(",") if x.strip()]
    if not versions:
        raise ValueError(f"No versions returned for {package}.")
    return versions[0]

def _safe_auto_version_npm(root: Path, package: str):
    code, text = _run_cmd(["npm", "view", package, "version", "--json"], root)
    if code != 0:
        raise ValueError(f"npm view failed for {package}: {text}")
    try:
        data = json.loads(text)
    except Exception:
        data = text.strip().strip('"')
    if isinstance(data, str) and data:
        return data
    raise ValueError(f"Could not resolve latest npm version for {package}.")

def _get_installed_version(root: Path, manager: str, package: str):
    if manager == "pip":
        code, text = _run_cmd([sys.executable, "-m", "pip", "show", package], root)
        if code != 0:
            return ""
        for ln in text.splitlines():
            if ln.lower().startswith("version:"):
                return ln.split(":", 1)[1].strip()
        return ""
    if manager == "npm":
        code, text = _run_cmd(["npm", "ls", package, "--depth=0", "--json"], root)
        if code != 0 and not text:
            return ""
        try:
            data = json.loads(text or "{}")
        except Exception:
            return ""
        deps = data.get("dependencies", {}) if isinstance(data, dict) else {}
        meta = deps.get(package) if isinstance(deps, dict) else None
        if isinstance(meta, dict):
            return str(meta.get("version", "")).strip()
        return ""
    return ""

def _post_change_compat_checks(root: Path, manager: str):
    checks = []
    if manager == "pip":
        checks.append(("pip check", [sys.executable, "-m", "pip", "check"]))
    elif manager == "npm":
        checks.append(("npm ls --depth=0", ["npm", "ls", "--depth=0"]))
    failures = []
    for label, cmd in checks:
        code, text = _run_cmd(cmd, root)
        if code != 0:
            failures.append(f"{label} failed: {text}")
    return failures

def _rollback_dependency_change(root: Path, manager: str, package: str, previous_version: str):
    if manager == "pip":
        if previous_version:
            code, text = _run_cmd([sys.executable, "-m", "pip", "install", f"{package}=={previous_version}"], root)
            return code == 0, text
        code, text = _run_cmd([sys.executable, "-m", "pip", "uninstall", "-y", package], root)
        return code == 0, text
    if manager == "npm":
        if previous_version:
            code, text = _run_cmd(["npm", "install", f"{package}@{previous_version}"], root)
            return code == 0, text
        code, text = _run_cmd(["npm", "uninstall", package], root)
        return code == 0, text
    return False, "Unsupported manager for rollback."

def _evaluate_dependency_risk(root: Path, manager: str, package: str, resolved_version: str, mode: str):
    policy = Policy.load(root, None)
    warnings = []
    if policy.is_denied(package):
        raise ValueError(f"Package '{package}' is denylisted by policy.")

    signals = MetadataSignals.load(root)
    meta = signals.get(manager, package)
    published = str(meta.get("published", "")).strip()
    if not published:
        warnings.append("No trusted package metadata found in local intelligence cache.")
    else:
        try:
            age_days = (datetime.now(timezone.utc).date() - datetime.fromisoformat(published).date()).days
            if age_days < 2:
                warnings.append(f"Package is very new ({age_days} day old).")
            elif age_days < 7:
                warnings.append(f"Package is recent ({age_days} days old).")
        except Exception:
            warnings.append("Package publish date is invalid/unreadable in metadata cache.")
    if mode == "auto" and not resolved_version:
        warnings.append("Auto mode could not determine a pinned version.")
    return warnings

def apply_dependency_action(root: Path, manager: str, action: str, package: str, version: str, mode: str, approved: bool, approval_note: str):
    if manager not in ("pip", "npm"):
        raise ValueError("Manager must be pip or npm.")
    if action not in ("install", "update", "uninstall"):
        raise ValueError("Action must be install, update, or uninstall.")
    if not _is_valid_package_name(package):
        raise ValueError("Invalid package name.")
    mode = mode if mode in ("manual", "auto") else "manual"

    # Always pre-check critical findings before mutating dependencies.
    pre, _ = run_scan_pipeline(
        root=root,
        policy_arg=None,
        out="security-artifacts",
        fail_on="CRITICAL",
        online_audit=False,
        sarif="",
        cyclonedx="",
        spdx="",
        html="",
    )
    if not pre.ok:
        raise ValueError("Blocked by CRITICAL findings. Resolve blockers before dependency changes.")

    resolved_version = version.strip()
    if action in ("install", "update"):
        if mode == "manual":
            if not _is_exact_version(resolved_version):
                raise ValueError("Manual install/update requires an exact version (example: 1.2.3).")
        else:
            if manager == "pip":
                resolved_version = _safe_auto_version_pip(root, package)
            else:
                resolved_version = _safe_auto_version_npm(root, package)

        risk_warnings = _evaluate_dependency_risk(root, manager, package, resolved_version, mode)
        if risk_warnings and not approved:
            joined = "; ".join(risk_warnings)
            raise ValueError(
                "Explicit approval required before this dependency change. "
                f"Risk notes: {joined}. Tick the approval checkbox and add a reason."
            )

    previous_version = _get_installed_version(root, manager, package)

    if manager == "pip":
        if action == "install":
            cmd = [sys.executable, "-m", "pip", "install", f"{package}=={resolved_version}"]
        elif action == "update":
            cmd = [sys.executable, "-m", "pip", "install", "--upgrade", f"{package}=={resolved_version}"]
        else:
            cmd = [sys.executable, "-m", "pip", "uninstall", "-y", package]
    else:
        if action == "install":
            cmd = ["npm", "install", f"{package}@{resolved_version}"]
        elif action == "update":
            cmd = ["npm", "install", f"{package}@{resolved_version}"]
        else:
            cmd = ["npm", "uninstall", package]

    code, text = _run_cmd(cmd, root)
    if code != 0:
        raise ValueError(f"{manager} {action} failed: {text}")

    compat_failures = _post_change_compat_checks(root, manager)
    if compat_failures:
        ok_rb, rb_text = _rollback_dependency_change(root, manager, package, previous_version)
        if ok_rb:
            raise ValueError(
                f"{manager} {action} failed compatibility checks and was rolled back. "
                f"Reason: {' | '.join(compat_failures)}"
            )
        raise ValueError(
            f"{manager} {action} failed compatibility checks and rollback also failed. "
            f"Reason: {' | '.join(compat_failures)} | rollback: {rb_text}"
        )

    post, _ = run_scan_pipeline(
        root=root,
        policy_arg=None,
        out="security-artifacts",
        fail_on="CRITICAL",
        online_audit=False,
        sarif="",
        cyclonedx="",
        spdx="",
        html="",
    )
    if not post.ok:
        raise ValueError(f"{manager} {action} applied, but post-check found CRITICAL issues. Review findings in UI.")

    ver_text = f" @{resolved_version}" if resolved_version else ""
    approved_msg = ""
    if action in ("install", "update") and approved:
        approved_msg = " Explicit approval confirmed."
    return (
        f"{manager} {action} completed for {package}{ver_text}. "
        f"Pre/post CRITICAL checks passed and compatibility checks passed.{approved_msg}"
    )

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

def cmd_setup(args):
    return _guard.cmd_setup(args)

def get_setup_status(root: Path):
    return _guard.get_setup_status(root)

def _guard_state_file(root: Path):
    return _guard._guard_state_file(root)

def _powershell_profile_candidates():
    return _guard._powershell_profile_candidates()

def _guard_profile_snippet(root: Path):
    return _guard._guard_profile_snippet(root)

def _load_guard_state(root: Path):
    return _guard._load_guard_state(root)

def _write_guard_state(root: Path, state: dict):
    return _guard._write_guard_state(root, state)

def _is_auto_guard_enabled(root: Path):
    return _guard._is_auto_guard_enabled(root)

def _set_powershell_autoguard(root: Path, enable: bool):
    return _guard._set_powershell_autoguard(root, enable)

def apply_guard_toggle(root: Path, action: str):
    return _guard.apply_guard_toggle(root, action)

def get_guard_mode_status(root: Path):
    return _guard.get_guard_mode_status(root)

def get_protection_scope(root: Path):
    return _guard.get_protection_scope(root)

def detect_official_repo_url(root: Path):
    return _guard.detect_official_repo_url(root)

def get_current_shell_guard_status(root: Path):
    return _guard.get_current_shell_guard_status(root)
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
    return len(suppress)

def upsert_approval_entry(root: Path, baseline_rel: str, manager: str, rule: str, package: str, file_value: str, expires: str):
    if not manager or not rule:
        raise ValueError("manager and rule are required")
    try:
        datetime.fromisoformat(expires).date()
    except Exception:
        raise ValueError("Invalid expires format. Use YYYY-MM-DD.")
    baseline_path = root / baseline_rel
    data = {"suppress": []}
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

def cmd_baseline(args):
    root = Path(args.path).resolve()
    report_path = root / args.report
    output_path = root / args.output
    if not report_path.exists():
        print(f"Missing report file: {report_path}")
        return 2
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Invalid report JSON: {e}")
        return 2
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        print("Invalid report format: findings must be a list")
        return 2
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
    print(f"Baseline written: {output_path} ({len(suppress)} entries)")
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

def main(argv=None):
    parser=argparse.ArgumentParser(prog="safedeps", description="Dependency policy gate for safer installs and updates.")
    sub=parser.add_subparsers(dest="cmd", required=True)
    p_help=sub.add_parser("help", help="Show quick usage commands for terminal/cmd/powershell")
    p_help.set_defaults(func=cmd_help)
    p_init=sub.add_parser("init", help="Create .safedeps/policy.json")
    p_init.add_argument("path", nargs="?", default=".")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)
    p_scan=sub.add_parser("scan", help="Scan a project before install/update")
    p_scan.add_argument("path", nargs="?", default=".")
    p_scan.add_argument("--policy")
    p_scan.add_argument("--out", default="security-artifacts")
    p_scan.add_argument("--sarif", default="", help="Optional SARIF output path (relative to scan root).")
    p_scan.add_argument("--cyclonedx", default="", help="Optional CycloneDX JSON output path (relative to scan root).")
    p_scan.add_argument("--spdx", default="", help="Optional SPDX JSON output path (relative to scan root).")
    p_scan.add_argument("--html", default="", help="Optional HTML output path (relative to scan root).")
    p_scan.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="HIGH")
    p_scan.add_argument("--online-audit", action="store_true", help="Run ecosystem audit commands when available. Requires network/tooling.")
    p_scan.set_defaults(func=cmd_scan)
    p_doctor=sub.add_parser("doctor", help="Validate local SafeDeps setup and metadata cache health")
    p_doctor.add_argument("path", nargs="?", default=".")
    p_doctor.set_defaults(func=cmd_doctor)
    p_explain=sub.add_parser("explain", help="Explain a finding rule and remediation intent")
    p_explain.add_argument("rule", help="Rule identifier (example: FLOATING_VERSION)")
    p_explain.set_defaults(func=cmd_explain)
    p_baseline=sub.add_parser("baseline", help="Create baseline suppression file from scan report")
    p_baseline.add_argument("path", nargs="?", default=".")
    p_baseline.add_argument("--report", default="security-artifacts/safedeps-report.json")
    p_baseline.add_argument("--output", default=".safedeps/vuln-baseline.json")
    p_baseline.set_defaults(func=cmd_baseline)
    p_approve=sub.add_parser("approve", help="Add expiring suppression entry to baseline file")
    p_approve.add_argument("path", nargs="?", default=".")
    p_approve.add_argument("--manager", required=True)
    p_approve.add_argument("--rule", required=True)
    p_approve.add_argument("--package", default="")
    p_approve.add_argument("--file", default="")
    p_approve.add_argument("--expires", required=True, help="Expiration date (YYYY-MM-DD)")
    p_approve.add_argument("--baseline", default=".safedeps/vuln-baseline.json")
    p_approve.set_defaults(func=cmd_approve)
    p_ui=sub.add_parser("ui", help="Run local web UI for visual scans")
    p_ui.add_argument("path", nargs="?", default=".")
    p_ui.add_argument("--host", default="127.0.0.1")
    p_ui.add_argument("--port", type=int, default=8765)
    p_ui.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="HIGH")
    p_ui.add_argument("--open-browser", action="store_true")
    p_ui.set_defaults(func=cmd_ui)
    p_setup=sub.add_parser("setup", help="One-time project setup for guarded pip install")
    p_setup.add_argument("path", nargs="?", default=".")
    p_setup.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="HIGH")
    p_setup.add_argument("--force", action="store_true")
    p_setup.set_defaults(func=cmd_setup)
    args=parser.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
