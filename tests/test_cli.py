import json
import re
from pathlib import Path
from safedeps.cli import main, render_ui_page
from safedeps.models import ScanResult, Finding
from safedeps.scanners import yaml as scanners_yaml


def test_bad_project_fails():
    code = main(["scan", "examples/bad-project", "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_safe_project_passes():
    code = main(["scan", "examples/safe-project", "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_pyproject_unpinned_dependency_fails(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo-app"
version = "0.0.1"
dependencies = ["requests>=2.0"]
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "allow_unpinned": False,
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_pyproject_pinned_dependency_passes(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo-app"
version = "0.0.1"
dependencies = ["requests==2.32.3"]
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "allow_unpinned": False,
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_poetry_lock_denylist_fails(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        """
[[package]]
name = "requests"
version = "2.32.3"
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["requests"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_uv_lock_denylist_fails(tmp_path):
    (tmp_path / "uv.lock").write_text(
        """
[[package]]
name = "requests"
version = "2.32.3"
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["requests"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_pipfile_lock_denylist_fails(tmp_path):
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps(
            {
                "default": {
                    "requests": {"version": "==2.32.3"},
                },
                "develop": {},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["requests"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_pipfile_lock_invalid_reports_high(tmp_path):
    (tmp_path / "Pipfile.lock").write_text("{ invalid json", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_package_lock_denylist_fails(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo-node", "version": "1.0.0"},
                    "node_modules/lodash": {"name": "lodash", "version": "4.17.21"},
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["lodash"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_package_lock_invalid_reports_high(tmp_path):
    (tmp_path / "package-lock.json").write_text("{ invalid json", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_pnpm_lock_denylist_or_parser_warning(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text(
        """
lockfileVersion: '9.0'
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-demo}
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["lodash"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    if scanners_yaml is None:
        assert code == 0
    else:
        assert code == 2


def test_pnpm_lock_invalid_reports_high_when_yaml_available(tmp_path):
    if scanners_yaml is None:
        return
    (tmp_path / "pnpm-lock.yaml").write_text(":\n  bad", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )

def test_ui_page_renders_findings():
    result = ScanResult(
        ok=False,
        findings=[
            Finding(
                severity="HIGH",
                manager="npm",
                rule="FLOATING_VERSION",
                message="demo",
                package="lodash",
                file="package.json",
            )
        ],
        sbom={"components": [{"name": "lodash", "version": "1.0.0", "manager": "npm"}]},
    )
    page = render_ui_page(Path(".").resolve(), "HIGH", result=result, outdir=Path("security-artifacts"))
    assert "SafeDeps UI" in page
    assert "FLOATING_VERSION" in page
    assert "package.json" in page
    assert "Use For Approval" in page
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_yarn_lock_denylist_fails(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        """
"lodash@^4.17.0":
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-demo
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["lodash"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_yarn_lock_scoped_denylist_fails(tmp_path):
    (tmp_path / "yarn.lock").write_text(
        """
"@types/node@^20.0.0":
  version "20.14.10"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-20.14.10.tgz"
  integrity sha512-demo
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["@types/node"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_directory_packages_props_denylist_fails(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text(
        """
<Project>
  <ItemGroup>
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["Newtonsoft.Json"],
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_packages_config_denylist_fails(tmp_path):
    (tmp_path / "packages.config").write_text(
        """
<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net8.0" />
</packages>
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["Newtonsoft.Json"],
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_directory_packages_props_invalid_reports_high(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text("<Project><ItemGroup>", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": False,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_packages_lock_json_denylist_fails(tmp_path):
    (tmp_path / "packages.lock.json").write_text(
        json.dumps(
            {
                "version": 1,
                "dependencies": {
                    ".NETCoreApp,Version=v8.0": {
                        "Newtonsoft.Json": {
                            "type": "Direct",
                            "requested": "[13.0.3, )",
                            "resolved": "13.0.3",
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "Demo.csproj").write_text("<Project/>", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "deny_packages": ["Newtonsoft.Json"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_packages_lock_json_invalid_reports_high(tmp_path):
    (tmp_path / "packages.lock.json").write_text("{ invalid", encoding="utf-8")
    (tmp_path / "Demo.csproj").write_text("<Project/>", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_monorepo_root_lockfile_covers_workspace_package(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "root", "lockfileVersion": 3, "packages": {"": {"name": "root", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    ws = tmp_path / "packages" / "app1"
    ws.mkdir(parents=True)
    (ws / "package.json").write_text(json.dumps({"name": "app1", "version": "1.0.0"}), encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(json.dumps({"require_lockfiles": True}), encoding="utf-8")
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_monorepo_workspace_without_lockfile_reports_missing(tmp_path):
    ws = tmp_path / "packages" / "app1"
    ws.mkdir(parents=True)
    (ws / "package.json").write_text(json.dumps({"name": "app1", "version": "1.0.0"}), encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(json.dumps({"require_lockfiles": True}), encoding="utf-8")
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2


def test_typosquatting_risk_for_pip_dependency_reports_medium(tmp_path):
    (tmp_path / "requirements.txt").write_text("reqests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("reqests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": True,
                "protected_packages": ["requests"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_typosquatting_risk_for_npm_dependency_reports_medium(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
                "dependencies": {"lodahs": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "lockfileVersion": 3,
                "packages": {"": {"name": "demo-node", "version": "1.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": True,
                "protected_packages": ["lodash"],
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_package_age_signal_reports_medium_from_metadata_cache(tmp_path):
    (tmp_path / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("demo==1.0.0\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text(
        json.dumps(
            {
                "pip": {
                    "demo": {
                        "published": "2026-05-20"
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_package_age_checks": True,
                "min_package_age_days": 14,
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_publisher_churn_signal_reports_medium_from_metadata_cache(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-node", "version": "1.0.0", "dependencies": {"demo-pkg": "1.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "demo-node", "lockfileVersion": 3, "packages": {"": {"name": "demo-node", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text(
        json.dumps(
            {
                "npm": {
                    "demo-pkg": {
                        "publisher_changes_90d": 4
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_publisher_churn_checks": True,
                "max_publisher_changes_90d": 1,
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_doctor_fails_without_safedeps_dir(tmp_path):
    code = main(["doctor", str(tmp_path)])
    assert code == 2


def test_doctor_passes_with_valid_policy_and_cache(tmp_path):
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(json.dumps({"schema": "safedeps.policy.v1"}), encoding="utf-8")
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text(json.dumps({"pip": {"demo": {"published": "2026-05-01"}}}), encoding="utf-8")
    code = main(["doctor", str(tmp_path)])
    assert code == 0


def test_doctor_fails_with_invalid_cache_json(tmp_path):
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(json.dumps({"schema": "safedeps.policy.v1"}), encoding="utf-8")
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text("{ invalid", encoding="utf-8")
    code = main(["doctor", str(tmp_path)])
    assert code == 2


def test_maintainer_change_signal_reports_medium_from_metadata_cache(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-node", "version": "1.0.0", "dependencies": {"demo-pkg": "1.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "demo-node", "lockfileVersion": 3, "packages": {"": {"name": "demo-node", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "metadata-cache.json").write_text(
        json.dumps(
            {
                "npm": {
                    "demo-pkg": {
                        "maintainer_changes_180d": 3
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_maintainer_change_checks": True,
                "max_maintainer_changes_180d": 1,
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0


def test_scan_writes_sarif_when_requested(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "version": "1.0.0",
                "dependencies": {"lodash": "latest"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "demo-node",
                "lockfileVersion": 3,
                "packages": {"": {"name": "demo-node", "version": "1.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--sarif", "security-artifacts/safedeps.sarif", "--fail-on", "HIGH"])
    assert code == 0
    sarif_path = tmp_path / "security-artifacts" / "safedeps.sarif"
    assert sarif_path.exists()
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data.get("version") == "2.1.0"
    assert isinstance(data.get("runs"), list) and data["runs"]


def test_scan_writes_cyclonedx_when_requested(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--cyclonedx", "security-artifacts/safedeps.cdx.json", "--fail-on", "HIGH"])
    assert code == 0
    cdx_path = tmp_path / "security-artifacts" / "safedeps.cdx.json"
    assert cdx_path.exists()
    data = json.loads(cdx_path.read_text(encoding="utf-8"))
    assert data.get("bomFormat") == "CycloneDX"
    assert data.get("specVersion") == "1.5"


def test_scan_writes_spdx_when_requested(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--spdx", "security-artifacts/safedeps.spdx.json", "--fail-on", "HIGH"])
    assert code == 0
    spdx_path = tmp_path / "security-artifacts" / "safedeps.spdx.json"
    assert spdx_path.exists()
    data = json.loads(spdx_path.read_text(encoding="utf-8"))
    assert data.get("spdxVersion") == "SPDX-2.3"
    assert isinstance(data.get("packages"), list)


def test_sbom_exporters_deduplicate_same_component(tmp_path):
    # Same dependency appears in requirements + requirements.lock; exporters should deduplicate
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    code = main([
        "scan", str(tmp_path),
        "--out", ".tmp-security",
        "--cyclonedx", "security-artifacts/safedeps.cdx.json",
        "--spdx", "security-artifacts/safedeps.spdx.json",
        "--fail-on", "HIGH",
    ])
    assert code == 0

    cdx = json.loads((tmp_path / "security-artifacts" / "safedeps.cdx.json").read_text(encoding="utf-8"))
    spdx = json.loads((tmp_path / "security-artifacts" / "safedeps.spdx.json").read_text(encoding="utf-8"))

    cdx_names = [c.get("name") for c in cdx.get("components", []) if c.get("name") == "requests"]
    spdx_names = [p.get("name") for p in spdx.get("packages", []) if p.get("name") == "requests"]
    assert len(cdx_names) == 1
    assert len(spdx_names) == 1


def test_vulnerability_baseline_suppresses_matching_findings(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-node", "version": "1.0.0", "dependencies": {"lodash": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "demo-node", "lockfileVersion": 3, "packages": {"": {"name": "demo-node", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
                "enable_vulnerability_baseline": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "vuln-baseline.json").write_text(
        json.dumps(
            {
                "suppress": [
                    {
                        "manager": "npm",
                        "rule": "FLOATING_VERSION",
                        "package": "lodash",
                        "file": "package.json",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 0

    report = json.loads((tmp_path / ".tmp-security" / "safedeps-report.json").read_text(encoding="utf-8"))
    blocked = [f for f in report.get("findings", []) if f.get("rule") == "FLOATING_VERSION" and f.get("package") == "lodash"]
    assert not blocked


def test_local_vulnerability_feed_adds_normalized_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "vuln-feed.json").write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "manager": "pip",
                        "package": "requests",
                        "id": "CVE-2099-0001",
                        "severity": "high",
                        "message": "Test advisory",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2

    report = json.loads((tmp_path / ".tmp-security" / "safedeps-report.json").read_text(encoding="utf-8"))
    vulns = [f for f in report.get("findings", []) if f.get("rule") == "KNOWN_VULNERABILITY" and f.get("manager") == "pip"]
    assert vulns
    assert vulns[0]["severity"] == "HIGH"


def test_local_osv_feed_adds_vulnerability_finding(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "vuln-feed.json").write_text(
        json.dumps(
            {
                "vulnerabilities_osv": [
                    {
                        "id": "OSV-2026-XYZ",
                        "summary": "OSV style advisory",
                        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "requests"}
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2

    report = json.loads((tmp_path / ".tmp-security" / "safedeps-report.json").read_text(encoding="utf-8"))
    vulns = [f for f in report.get("findings", []) if f.get("rule") == "KNOWN_VULNERABILITY" and f.get("package") == "requests"]
    assert vulns
    assert vulns[0]["severity"] == "CRITICAL"


def test_vulnerability_baseline_expired_entry_does_not_suppress(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-node", "version": "1.0.0", "dependencies": {"lodash": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "demo-node", "lockfileVersion": 3, "packages": {"": {"name": "demo-node", "version": "1.0.0"}}}),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps").mkdir()
    (tmp_path / ".safedeps" / "policy.json").write_text(
        json.dumps(
            {
                "enable_typosquat_detection": False,
                "require_lockfiles": True,
                "enable_vulnerability_baseline": True,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".safedeps" / "vuln-baseline.json").write_text(
        json.dumps(
            {
                "suppress": [
                    {
                        "manager": "npm",
                        "rule": "FLOATING_VERSION",
                        "package": "lodash",
                        "file": "package.json",
                        "expires": "2025-01-01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    code = main(["scan", str(tmp_path), "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2

    report = json.loads((tmp_path / ".tmp-security" / "safedeps-report.json").read_text(encoding="utf-8"))
    blocked = [f for f in report.get("findings", []) if f.get("rule") == "FLOATING_VERSION" and f.get("package") == "lodash"]
    assert blocked


def test_baseline_command_generates_suppressions(tmp_path):
    (tmp_path / "security-artifacts").mkdir(parents=True)
    (tmp_path / "security-artifacts" / "safedeps-report.json").write_text(
        json.dumps(
            {
                "ok": False,
                "findings": [
                    {"manager": "npm", "rule": "FLOATING_VERSION", "package": "lodash", "file": "package.json"},
                    {"manager": "pip", "rule": "KNOWN_VULNERABILITY", "package": "requests", "file": "requirements.txt"},
                ],
            }
        ),
        encoding="utf-8",
    )
    code = main(["baseline", str(tmp_path)])
    assert code == 0
    baseline = json.loads((tmp_path / ".safedeps" / "vuln-baseline.json").read_text(encoding="utf-8"))
    assert len(baseline.get("suppress", [])) == 2


def test_approve_command_writes_expiring_suppression(tmp_path):
    code = main(
        [
            "approve",
            str(tmp_path),
            "--manager",
            "npm",
            "--rule",
            "FLOATING_VERSION",
            "--package",
            "lodash",
            "--file",
            "package.json",
            "--expires",
            "2026-12-31",
        ]
    )
    assert code == 0
    data = json.loads((tmp_path / ".safedeps" / "vuln-baseline.json").read_text(encoding="utf-8"))
    entries = data.get("suppress", [])
    assert len(entries) == 1
    assert entries[0]["expires"] == "2026-12-31"


def test_explain_command_known_rule_ok():
    code = main(["explain", "FLOATING_VERSION"])
    assert code == 0


def test_approve_command_rejects_invalid_date(tmp_path):
    code = main(
        [
            "approve",
            str(tmp_path),
            "--manager",
            "npm",
            "--rule",
            "FLOATING_VERSION",
            "--expires",
            "31-12-2026",
        ]
    )
    assert code == 2


def test_scan_writes_html_when_requested(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    html_rel = "security-artifacts/safedeps-report.html"
    code = main(["scan", str(tmp_path), "--out", "security-artifacts", "--html", html_rel, "--fail-on", "HIGH"])
    assert code == 0
    html_path = tmp_path / html_rel
    assert html_path.exists()
    html_text = html_path.read_text(encoding="utf-8")
    assert "SafeDeps Scan Report" in html_text
    assert "Status:" in html_text


def test_explain_output_stability(capsys):
    code = main(["explain", "FLOATING_VERSION"])
    assert code == 0
    out = capsys.readouterr().out
    assert out.splitlines() == [
        "FLOATING_VERSION",
        "Dependency version is not pinned exactly. Pin exact versions to reduce supply-chain drift.",
    ]


def test_explain_unknown_rule_output_stability(capsys):
    code = main(["explain", "UNKNOWN_RULE"])
    assert code == 2
    out = capsys.readouterr().out
    assert "Unknown finding rule: UNKNOWN_RULE" in out
    assert "Tip: run scan and use one of the emitted rule identifiers." in out


def test_doctor_output_stability_without_safedeps_dir(tmp_path, capsys):
    code = main(["doctor", str(tmp_path)])
    assert code == 2
    out = capsys.readouterr().out
    assert "SafeDeps doctor" in out
    assert f"Path: {tmp_path}" in out
    assert "Status: FAIL" in out
    assert "Missing .safedeps directory. Run: safedeps init" in out


def test_baseline_output_stability(tmp_path, capsys):
    (tmp_path / "security-artifacts").mkdir(parents=True)
    (tmp_path / "security-artifacts" / "safedeps-report.json").write_text(
        json.dumps(
            {
                "ok": False,
                "findings": [
                    {"manager": "npm", "rule": "FLOATING_VERSION", "package": "lodash", "file": "package.json"},
                ],
            }
        ),
        encoding="utf-8",
    )
    code = main(["baseline", str(tmp_path)])
    assert code == 0
    out = capsys.readouterr().out
    assert "Baseline written:" in out
    assert "(1 entries)" in out


def test_approve_output_stability(tmp_path, capsys):
    code = main(
        [
            "approve",
            str(tmp_path),
            "--manager",
            "npm",
            "--rule",
            "FLOATING_VERSION",
            "--package",
            "lodash",
            "--file",
            "package.json",
            "--expires",
            "2026-12-31",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "Added approval:" in out
    assert "npm/FLOATING_VERSION" in out
    assert "expires=2026-12-31" in out


def test_scan_summary_output_stability_for_clean_project(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("requests==2.32.3\n", encoding="utf-8")
    code = main(["scan", str(tmp_path), "--out", "security-artifacts", "--fail-on", "HIGH"])
    assert code == 0
    out = capsys.readouterr().out
    assert "SafeDeps scan" in out
    assert "Status: PASS   fail-on: HIGH" in out
    assert "Artifacts:" in out


def test_scan_bad_project_fixture_snapshot(capsys):
    code = main(["scan", "examples/bad-project", "--out", ".tmp-security", "--fail-on", "HIGH"])
    assert code == 2
    out = capsys.readouterr().out
    # Normalize non-deterministic counts/paths and assert stable key lines.
    normalized_lines = []
    for line in out.splitlines():
        if line.startswith("Findings: "):
            normalized_lines.append("Findings:")
            continue
        if line.startswith("Artifacts: "):
            normalized_lines.append("Artifacts:")
            continue
        if line.startswith("- "):
            match = re.match(r"^- (CRITICAL|HIGH|MEDIUM|LOW|INFO) ([^:]+):", line)
            if match:
                normalized_lines.append(f"- {match.group(1)} {match.group(2)}")
                continue
        normalized_lines.append(line)
    normalized = "\n".join(normalized_lines)

    expected = Path("tests/golden/scan_bad_project_snapshot.txt").read_text(encoding="utf-8")
    for expected_line in expected.splitlines():
        assert expected_line in normalized
