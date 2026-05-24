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
from .vulnerability_intel import load_local_vulnerability_findings

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

    class UIHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/":
                self.send_error(404)
                return
            body = render_ui_page(start_path, default_fail_on)
            self._send_html(body)

        def do_POST(self):
            if self.path not in ("/scan", "/explain", "/baseline", "/approve", "/setup", "/intelligence"):
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
                    body = render_ui_page(scan_path, fail_on, notice=f"{rule}: {text}", ui_state=ui_state)
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
                    body = render_ui_page(
                        scan_path,
                        fail_on,
                        notice="Project setup completed. Activate guard with: source .safedeps/activate.sh",
                        ui_state=ui_state,
                    )
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
                body = render_ui_page(scan_path, fail_on, error=str(e), ui_state=ui_state)
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
    :root {{ --bg:#f4f6f8; --panel:#ffffff; --ink:#14213d; --accent:#2a9d8f; --danger:#b00020; }}
    body {{ margin:0; font-family: "Segoe UI", "Helvetica Neue", sans-serif; background:linear-gradient(120deg,#e9f1f7,#f8f5ef); color:var(--ink); }}
    .wrap {{ max-width: 1100px; margin: 28px auto; padding: 0 16px; }}
    .panel {{ background:var(--panel); border-radius:14px; padding:20px; box-shadow:0 12px 30px rgba(20,33,61,0.08); }}
    h1 {{ margin:0 0 8px; }}
    .sub {{ margin:0 0 16px; opacity:.8; }}
    form {{ display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-bottom: 18px; }}
    label {{ display:block; font-size:13px; margin-bottom:4px; }}
    input, select {{ width:100%; box-sizing:border-box; padding:10px; border:1px solid #d7dce2; border-radius:10px; }}
    textarea {{ width:100%; min-height:160px; box-sizing:border-box; padding:10px; border:1px solid #d7dce2; border-radius:10px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .full {{ grid-column:1 / -1; }}
    .actions {{ display:flex; gap:12px; align-items:center; }}
    button {{ background:var(--accent); color:#fff; border:0; border-radius:10px; padding:10px 16px; font-weight:700; cursor:pointer; }}
    .status {{ margin-top:16px; padding:12px; border-radius:10px; font-weight:600; }}
    .status.ok {{ background:#e6f6f3; color:#0d6b60; }}
    .status.fail {{ background:#fdecef; color:#8a1227; }}
    .notice {{ margin-top:16px; background:#e7f0ff; color:#123b74; padding:12px; border-radius:10px; }}
    .error {{ margin-top:16px; background:#fdecef; color:#8a1227; padding:12px; border-radius:10px; }}
    .hint {{ margin-top:10px; font-size:12px; opacity:.75; }}
    .pick {{ background:#2f5d8a; }}
    table {{ width:100%; border-collapse:collapse; margin-top:14px; }}
    th, td {{ border-bottom:1px solid #e8edf3; text-align:left; padding:8px; font-size:14px; vertical-align:top; }}
    th {{ background:#f5f8fc; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="panel">
      <h1>SafeDeps UI</h1>
      <p class="sub">Visual dependency security scans with policy-aware outputs.</p>
      <div class="hint">Setup status: {_html_escape(setup_status)}</div>
      <form method="post" action="/setup">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div class="full actions"><button type="submit">Setup Project Guard</button></div>
      </form>
      <form method="post" action="/scan">
        <div class="full"><label>Project path</label><input name="path" value="{_html_escape(state['path'])}" /></div>
        <div><label>Fail on</label><select name="fail_on">{options}</select></div>
        <div><label>Output dir</label><input name="out" value="{_html_escape(state['out'])}" /></div>
        <div><label>Policy file (optional)</label><input name="policy" value="{_html_escape(state['policy'])}" placeholder=".safedeps/policy.json" /></div>
        <div><label>SARIF path (optional)</label><input name="sarif" value="{_html_escape(state['sarif'])}" placeholder="security-artifacts/safedeps.sarif" /></div>
        <div><label>CycloneDX path (optional)</label><input name="cyclonedx" value="{_html_escape(state['cyclonedx'])}" placeholder="security-artifacts/safedeps.cdx.json" /></div>
        <div><label>SPDX path (optional)</label><input name="spdx" value="{_html_escape(state['spdx'])}" placeholder="security-artifacts/safedeps.spdx.json" /></div>
        <div><label>HTML path (optional)</label><input name="html" value="{_html_escape(state['html'])}" placeholder="security-artifacts/safedeps-report.html" /></div>
        <div class="full actions">
          <label><input type="checkbox" name="online_audit"{checked}> Online audit</label>
          <button type="submit">Run Scan</button>
        </div>
      </form>
      <form method="post" action="/explain">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div><label>Explain rule</label><input name="rule" value="{_html_escape(state['rule'])}" placeholder="FLOATING_VERSION" /></div>
        <div class="actions"><button type="submit">Explain Rule</button></div>
      </form>
      <form method="post" action="/baseline">
        <input type="hidden" name="path" value="{_html_escape(state['path'])}" />
        <input type="hidden" name="fail_on" value="{_html_escape(state['fail_on'])}" />
        <div><label>Report path</label><input name="report" value="{_html_escape(state['report'])}" /></div>
        <div><label>Baseline output path</label><input name="baseline_output" value="{_html_escape(state['baseline_output'])}" /></div>
        <div class="full actions"><button type="submit">Create Baseline</button></div>
      </form>
      <form method="post" action="/approve" id="approve-form">
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
      <form method="post" action="/intelligence">
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
      {status_html}
      {render_pip_guard_panel(result, state["fail_on"]) if result is not None else ""}
      {render_findings_table(result) if result is not None else ""}
    </div>
  </div>
  <script>
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
    root = Path(args.path).resolve()
    fail_on = args.fail_on
    cmd_init(argparse.Namespace(path=str(root), force=args.force))
    bindir = root / ".safedeps" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)

    wrapper = f"""#!/usr/bin/env bash
set -euo pipefail

REAL_PIP="$(python3 -c 'import sys; print(sys.executable)' 2>/dev/null || command -v python3 || true)"
if [ -z "${{REAL_PIP}}" ]; then
  echo "python3 not found; cannot execute pip safely."
  exit 2
fi

if [ "${{1:-}}" = "install" ]; then
  if ! safedeps scan . --fail-on {fail_on}; then
    echo "SafeDeps blocked pip install due to policy/security findings."
    echo "Open UI: safedeps ui . --open-browser"
    exit 2
  fi
fi

exec "${{REAL_PIP}}" -m pip "$@"
"""
    pip_path = bindir / "pip"
    pip3_path = bindir / "pip3"
    pip_path.write_text(wrapper, encoding="utf-8")
    pip3_path.write_text(wrapper, encoding="utf-8")
    os.chmod(pip_path, 0o755)
    os.chmod(pip3_path, 0o755)

    activate = root / ".safedeps" / "activate.sh"
    activate.write_text(
        "#!/usr/bin/env bash\n"
        'export PATH="$PWD/.safedeps/bin:$PATH"\n'
        'echo "SafeDeps pip guard active for this shell."\n',
        encoding="utf-8",
    )
    os.chmod(activate, 0o755)

    print("SafeDeps setup completed.")
    print(f"- Guard wrappers: {pip_path} and {pip3_path}")
    print(f"- Activate in shell: source {activate}")
    print("- After activation, pip install is guarded automatically in this project.")
    return 0

def get_setup_status(root: Path):
    pip_wrapper = root / ".safedeps" / "bin" / "pip"
    activate = root / ".safedeps" / "activate.sh"
    policy = root / ".safedeps" / "policy.json"
    missing = []
    if not policy.exists():
        missing.append("policy")
    if not pip_wrapper.exists():
        missing.append("pip wrapper")
    if not activate.exists():
        missing.append("activate script")
    if missing:
        return f"Not configured ({', '.join(missing)} missing). Run: safedeps setup ."
    return "Configured. Activate with: source .safedeps/activate.sh"

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
