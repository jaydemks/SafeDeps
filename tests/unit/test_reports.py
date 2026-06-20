import json

from safedeps import __version__
from safedeps.models import Finding, ScanResult
from safedeps.policy import Policy
from safedeps.reports import (
    _component_ref,
    _finding_fingerprint_from_dict,
    _purl_for,
    _unique_components,
    REPORT_RENDERERS,
    apply_vulnerability_baseline,
    finding_fingerprint,
    to_cyclonedx,
    to_html_report,
    to_sarif,
    to_spdx,
    write_scan_outputs,
)


def test_vulnerability_baseline_suppresses_matching_finding(tmp_path):
    finding = Finding(
        severity="HIGH",
        manager="pip",
        rule="KNOWN_VULNERABILITY",
        package="requests",
        file="requirements.txt",
        message="blocked",
    )
    baseline = tmp_path / ".safedeps" / "vuln-baseline.json"
    baseline.parent.mkdir()
    baseline.write_text(
        json.dumps(
            {
                "suppress": [
                    {
                        "manager": "pip",
                        "rule": "KNOWN_VULNERABILITY",
                        "package": "requests",
                        "file": "requirements.txt",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    policy = Policy({"enable_vulnerability_baseline": True})

    assert apply_vulnerability_baseline(tmp_path, policy, [finding]) == []


def test_vulnerability_baseline_ignores_invalid_json(tmp_path):
    finding = Finding("HIGH", "pip", "KNOWN_VULNERABILITY", "blocked", package="requests")
    baseline = tmp_path / ".safedeps" / "vuln-baseline.json"
    baseline.parent.mkdir()
    baseline.write_text("{ invalid", encoding="utf-8")

    assert apply_vulnerability_baseline(tmp_path, Policy({}), [finding]) == [finding]


def test_finding_fingerprint_is_case_normalized():
    finding = Finding("HIGH", "PIP", "floating_version", "blocked", "Req.txt", "Requests")

    assert finding_fingerprint(finding) == "pip|FLOATING_VERSION|requests|Req.txt"
    assert _finding_fingerprint_from_dict(
        {"manager": "PIP", "rule": "floating_version", "package": "Requests", "file": "Req.txt"}
    ) == finding_fingerprint(finding)


def test_unique_components_keeps_manager_name_version_scope_identity():
    components = [
        {"manager": "pip", "name": "Requests", "version": "2.32.3", "scope": "runtime"},
        {"manager": "pip", "name": "requests", "version": "2.32.3", "scope": "runtime"},
        {"manager": "pip", "name": "requests", "version": "2.32.3", "scope": "dev"},
    ]

    assert _unique_components(components) == [components[0], components[2]]


def test_sbom_reporters_emit_expected_package_references():
    result = ScanResult(
        ok=False,
        findings=[
            Finding("HIGH", "pip", "FLOATING_VERSION", "blocked", "requirements.txt", "requests")
        ],
        sbom={
            "components": [
                {"manager": "pip", "name": "requests", "version": "2.32.3", "scope": "runtime"}
            ]
        },
    )

    sarif = to_sarif(result)
    cyclonedx = to_cyclonedx(result)
    spdx = to_spdx(result)

    assert sarif["runs"][0]["results"][0]["level"] == "error"
    assert cyclonedx["components"][0]["purl"] == "pkg:pypi/requests@2.32.3"
    assert spdx["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:pypi/requests@2.32.3"


def test_purl_and_component_ref_helpers_cover_known_managers():
    assert _purl_for("npm", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"
    assert _purl_for("pip", "requests", "") == "pkg:pypi/requests"
    assert _purl_for("nuget", "Newtonsoft.Json", "13.0.3") == "pkg:nuget/Newtonsoft.Json@13.0.3"
    assert _purl_for("other", "pkg", "1") == "pkg:generic/pkg@1"
    assert _component_ref("pip", "requests", "2.32.3", "runtime").endswith("#runtime")


def _mixed_report_result():
    return ScanResult(
        ok=False,
        findings=[
            Finding(
                severity="LOW",
                manager="pip",
                rule="UNPINNED_VERSION",
                message="Pin requests",
                file="requirements.txt",
                package="requests",
            ),
            Finding(
                severity="HIGH",
                manager="npm",
                rule="FLOATING_VERSION",
                message="Avoid <latest> & floating ranges",
                file="web/package.json",
                package="left-pad",
            ),
            Finding(
                severity="MEDIUM",
                manager="nuget",
                rule="KNOWN_VULNERABILITY",
                message='Upgrade "Newtonsoft.Json"',
                file="src/App.csproj",
                package="Newtonsoft.Json",
            ),
        ],
        sbom={
            "components": [
                {"manager": "pip", "name": "requests", "version": "2.32.3", "scope": "runtime"},
                {"manager": "pip", "name": "Requests", "version": "2.32.3", "scope": "runtime"},
                {"manager": "npm", "name": "left-pad", "version": "1.3.0", "scope": "dev"},
                {
                    "manager": "nuget",
                    "name": "Newtonsoft.Json",
                    "version": "13.0.3",
                    "scope": "runtime",
                },
            ]
        },
    )


def test_sarif_output_stable_shape_rules_and_relative_locations():
    sarif = to_sarif(_mixed_report_result())

    assert sarif == {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SafeDeps",
                        "semanticVersion": __version__,
                        "rules": [
                            {
                                "id": "npm:FLOATING_VERSION",
                                "name": "FLOATING_VERSION",
                                "shortDescription": {"text": "npm FLOATING_VERSION"},
                                "helpUri": "https://github.com/",
                            },
                            {
                                "id": "nuget:KNOWN_VULNERABILITY",
                                "name": "KNOWN_VULNERABILITY",
                                "shortDescription": {"text": "nuget KNOWN_VULNERABILITY"},
                                "helpUri": "https://github.com/",
                            },
                            {
                                "id": "pip:UNPINNED_VERSION",
                                "name": "UNPINNED_VERSION",
                                "shortDescription": {"text": "pip UNPINNED_VERSION"},
                                "helpUri": "https://github.com/",
                            },
                        ],
                    }
                },
                "invocations": [{"executionSuccessful": False}],
                "results": [
                    {
                        "ruleId": "pip:UNPINNED_VERSION",
                        "level": "note",
                        "message": {"text": "Pin requests"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "requirements.txt"}
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "npm:FLOATING_VERSION",
                        "level": "error",
                        "message": {"text": "Avoid <latest> & floating ranges"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "web/package.json"}
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "nuget:KNOWN_VULNERABILITY",
                        "level": "warning",
                        "message": {"text": 'Upgrade "Newtonsoft.Json"'},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/App.csproj"}
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }


def test_cyclonedx_output_stable_after_normalizing_generated_metadata():
    cyclonedx = to_cyclonedx(_mixed_report_result())
    cyclonedx["serialNumber"] = "<serial>"
    cyclonedx["metadata"]["timestamp"] = "<timestamp>"

    assert cyclonedx == {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": "<serial>",
        "metadata": {
            "timestamp": "<timestamp>",
            "tools": [{"vendor": "SafeDeps", "name": "safedeps", "version": __version__}],
        },
        "components": [
            {
                "type": "library",
                "name": "requests",
                "bom-ref": "pkg:pypi/requests@2.32.3#runtime",
                "version": "2.32.3",
                "purl": "pkg:pypi/requests@2.32.3",
            },
            {
                "type": "library",
                "name": "left-pad",
                "bom-ref": "pkg:npm/left-pad@1.3.0#dev",
                "version": "1.3.0",
                "purl": "pkg:npm/left-pad@1.3.0",
            },
            {
                "type": "library",
                "name": "Newtonsoft.Json",
                "bom-ref": "pkg:nuget/Newtonsoft.Json@13.0.3#runtime",
                "version": "13.0.3",
                "purl": "pkg:nuget/Newtonsoft.Json@13.0.3",
            },
        ],
    }


def test_spdx_output_stable_after_normalizing_creation_timestamp():
    spdx = to_spdx(_mixed_report_result())
    spdx["creationInfo"]["created"] = "<created>"

    assert spdx == {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "safedeps-sbom",
        "documentNamespace": "https://safedeps.local/spdx/safedeps-sbom",
        "creationInfo": {
            "creators": ["Tool: safedeps"],
            "created": "<created>",
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-1",
                "name": "requests",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "versionInfo": "2.32.3",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/requests@2.32.3",
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-Package-2",
                "name": "left-pad",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "versionInfo": "1.3.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/left-pad@1.3.0",
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-Package-3",
                "name": "Newtonsoft.Json",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "versionInfo": "13.0.3",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:nuget/Newtonsoft.Json@13.0.3",
                    }
                ],
            },
        ],
    }


def test_html_report_orders_findings_by_severity_and_escapes_cells():
    html = to_html_report(_mixed_report_result(), "HIGH")

    high = html.index("<td>HIGH</td>")
    medium = html.index("<td>MEDIUM</td>")
    low = html.index("<td>LOW</td>")
    assert high < medium < low
    assert "Status: <span class=\"status-fail\">FAIL</span>" in html
    assert "<div>Fail threshold: HIGH</div>" in html
    assert "<div>Findings: 3</div>" in html
    assert "<div>Components: 4</div>" in html
    assert "<td>Avoid &lt;latest&gt; &amp; floating ranges</td>" in html
    assert "<td>Upgrade &quot;Newtonsoft.Json&quot;</td>" in html
    assert "/mnt/" not in html


def test_write_scan_outputs_writes_default_and_optional_report_formats(tmp_path):
    result = _mixed_report_result()
    assert set(REPORT_RENDERERS) == {"sarif", "cyclonedx", "spdx", "html"}

    outdir = write_scan_outputs(
        result,
        tmp_path,
        "security-artifacts",
        fail_on="HIGH",
        sarif="reports/safedeps.sarif",
        cyclonedx="reports/safedeps.cdx.json",
        spdx="reports/safedeps.spdx.json",
        html="reports/safedeps.html",
    )

    assert outdir == tmp_path / "security-artifacts"
    assert json.loads((outdir / "safedeps-report.json").read_text(encoding="utf-8"))["ok"] is False
    assert json.loads((outdir / "safedeps-sbom.json").read_text(encoding="utf-8"))["components"]
    assert json.loads((tmp_path / "reports" / "safedeps.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert json.loads((tmp_path / "reports" / "safedeps.cdx.json").read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"
    assert json.loads((tmp_path / "reports" / "safedeps.spdx.json").read_text(encoding="utf-8"))["spdxVersion"] == "SPDX-2.3"
    assert "SafeDeps Scan Report" in (tmp_path / "reports" / "safedeps.html").read_text(encoding="utf-8")
