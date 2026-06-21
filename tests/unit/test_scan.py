import json
from types import SimpleNamespace

import safedeps.scan as scan
from safedeps.models import Finding


class FakeScanner:
    def __init__(self, findings=None, components=None):
        self.findings = findings or []
        self.components = components or []

    def scan(self, root, policy):
        return list(self.findings), list(self.components)


def test_run_scan_pipeline_writes_reports_and_applies_threshold(monkeypatch, tmp_path):
    finding = Finding("HIGH", "pip", "FLOATING_VERSION", "blocked", "requirements.txt", "requests")
    component = {"manager": "pip", "name": "requests", "version": "2.32.3"}
    monkeypatch.setattr(scan, "PACKAGE_MANAGER_ADAPTERS", [FakeScanner([finding], [component])])
    monkeypatch.setattr(scan, "load_local_vulnerability_findings", lambda root, components, policy: [])
    monkeypatch.setattr(scan, "apply_vulnerability_baseline", lambda root, policy, findings: findings)

    result, outdir = scan.run_scan_pipeline(
        root=tmp_path,
        policy_arg=None,
        out="security-artifacts",
        fail_on="HIGH",
        online_audit=False,
        sarif="reports/safedeps.sarif",
        cyclonedx="reports/safedeps.cdx.json",
        spdx="reports/safedeps.spdx.json",
        html="reports/safedeps.html",
    )

    assert result.ok is False
    assert outdir == tmp_path / "security-artifacts"
    report = json.loads((outdir / "safedeps-report.json").read_text(encoding="utf-8"))
    sbom = json.loads((outdir / "safedeps-sbom.json").read_text(encoding="utf-8"))
    assert report["findings"][0]["rule"] == "FLOATING_VERSION"
    assert sbom["components"] == [component]
    assert (tmp_path / "reports" / "safedeps.sarif").exists()
    assert (tmp_path / "reports" / "safedeps.cdx.json").exists()
    assert (tmp_path / "reports" / "safedeps.spdx.json").exists()
    assert (tmp_path / "reports" / "safedeps.html").exists()


def test_run_scan_pipeline_uses_baseline_and_online_audit(monkeypatch, tmp_path):
    scanner_finding = Finding("LOW", "pip", "LOW_SIGNAL", "low")
    audit_finding = Finding("HIGH", "npm", "NPM_AUDIT", "audit")
    monkeypatch.setattr(scan, "PACKAGE_MANAGER_ADAPTERS", [FakeScanner([scanner_finding], [])])
    monkeypatch.setattr(scan, "load_local_vulnerability_findings", lambda root, components, policy: [])
    monkeypatch.setattr(scan, "run_online_audits", lambda root: [audit_finding])
    monkeypatch.setattr(
        scan,
        "apply_vulnerability_baseline",
        lambda root, policy, findings: [f for f in findings if f.rule != "NPM_AUDIT"],
    )

    result, _ = scan.run_scan_pipeline(
        root=tmp_path,
        policy_arg=None,
        out="out",
        fail_on="MEDIUM",
        online_audit=True,
        sarif="",
        cyclonedx="",
        spdx="",
        html="",
    )

    assert result.ok is True
    assert [finding.rule for finding in result.findings] == ["LOW_SIGNAL"]


def test_run_scan_pipeline_applies_osv_version_range_intelligence(monkeypatch, tmp_path):
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "vuln-feed.json").write_text(
        json.dumps(
            {
                "vulnerabilities_osv": [
                    {
                        "id": "OSV-RANGE",
                        "summary": "affected range",
                        "database_specific": {"severity": "critical"},
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "requests"},
                                "ranges": [
                                    {
                                        "events": [
                                            {"introduced": "2.0.0"},
                                            {"fixed": "2.32.0"},
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        scan,
        "PACKAGE_MANAGER_ADAPTERS",
        [
            FakeScanner(
                components=[
                    {
                        "manager": "pip",
                        "name": "requests",
                        "version": "==2.31.0",
                        "file": "requirements.txt",
                    }
                ]
            )
        ],
    )
    monkeypatch.setattr(scan, "apply_vulnerability_baseline", lambda root, policy, findings: findings)

    result, _ = scan.run_scan_pipeline(
        root=tmp_path,
        policy_arg=None,
        out="out",
        fail_on="HIGH",
        online_audit=False,
        sarif="",
        cyclonedx="",
        spdx="",
        html="",
    )

    assert result.ok is False
    assert [finding.rule for finding in result.findings] == ["KNOWN_VULNERABILITY"]
    assert "OSV-RANGE" in result.findings[0].message


def test_run_online_audits_adds_high_npm_finding(monkeypatch, tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout=json.dumps({"metadata": {"vulnerabilities": {"high": 1, "critical": 0}}})
        ),
    )

    findings = scan.run_online_audits(tmp_path)

    assert len(findings) == 1
    assert findings[0].rule == "NPM_AUDIT"


def test_run_online_audits_reports_unavailable_audit(monkeypatch, tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")

    def fail(*args, **kwargs):
        raise OSError("npm missing")

    monkeypatch.setattr(scan.subprocess, "run", fail)

    findings = scan.run_online_audits(tmp_path)

    assert len(findings) == 1
    assert findings[0].rule == "AUDIT_UNAVAILABLE"


def test_run_online_audits_skips_when_no_node_project(tmp_path):
    assert scan.run_online_audits(tmp_path) == []
