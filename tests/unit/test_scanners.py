import json

import pytest

from safedeps.models import PackageTarget
from safedeps.package_managers import (
    DEFAULT_PACKAGE_MANAGER_ADAPTERS,
    PackageManagerAdapter,
    adapters_by_manager,
)
from safedeps.policy import Policy
from safedeps.scanners import SCANNERS
from safedeps.scanners.base import Scanner, iter_files, path_is_excluded, severity_for_exception
from safedeps.scanners.git_scanner import GitScanner
from safedeps.scanners.npm_scanner import NpmScanner
from safedeps.scanners.nuget_scanner import NugetScanner
from safedeps.scanners.pip_scanner import PipScanner


def _policy(**overrides):
    data = {
        "allow_unpinned": False,
        "require_lockfiles": False,
        "allowed_registries": {
            "pip": ["https://pypi.org/simple"],
            "npm": ["https://registry.npmjs.org/"],
            "nuget": ["https://api.nuget.org/v3/index.json"],
        },
        "deny_packages": ["blocked"],
        "exceptions": [],
    }
    data.update(overrides)
    return Policy(data)


def _rules(findings):
    return [finding.rule for finding in findings]


def test_scanner_adapter_metadata_and_package_target_component_shape(tmp_path):
    scanner = Scanner()
    assert scanner.scan(tmp_path, _policy()) == ([], [])
    component = scanner.component_from_target(
        PackageTarget(manager="pip", name="requests", version="2.32.3", file="requirements.txt", scope="runtime")
    )

    assert component == {
        "type": "library",
        "manager": "pip",
        "name": "requests",
        "version": "2.32.3",
        "scope": "runtime",
        "file": "requirements.txt",
    }
    metadata = {scanner.manager: scanner for scanner in SCANNERS}
    assert metadata["pip"].supports_runtime_guard is True
    assert metadata["npm"].supports_runtime_guard is False
    assert "requirements*.txt" in metadata["pip"].manifests
    assert "package-lock.json" in metadata["npm"].lockfiles
    assert "*.csproj" in metadata["nuget"].manifests
    assert ".gitmodules" in metadata["git"].manifests


def test_base_iter_files_skips_transient_directories_and_matches_patterns(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "requirements-dev.txt").write_text("pytest==8.0.0", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "requirements.txt").write_text("ignored==1", encoding="utf-8")
    (tmp_path / ".venv-local").mkdir()
    (tmp_path / ".venv-local" / "requirements.txt").write_text("ignored==1", encoding="utf-8")

    matches = sorted(path.relative_to(tmp_path).as_posix() for path in iter_files(tmp_path, "requirements*.txt"))

    assert matches == ["nested/requirements-dev.txt", "requirements.txt"]


def test_base_path_exclusion_handles_relative_outside_and_empty_policy_entries(tmp_path):
    policy = _policy(exclude_paths=["examples/", "", None])

    assert path_is_excluded(tmp_path, tmp_path / "examples" / "bad-project" / "package.json", policy)
    assert path_is_excluded(tmp_path, tmp_path / "examples", policy)
    assert not path_is_excluded(tmp_path, tmp_path / "src" / "package.json", policy)
    assert not path_is_excluded(tmp_path, tmp_path.parent / "outside" / "package.json", _policy())


def test_severity_for_exception_returns_info_for_matching_exception():
    tomorrow_policy = _policy(
        require_expiring_exceptions=False,
        exceptions=[{"manager": "pip", "package": "requests", "rule": "UNPINNED_VERSION"}],
    )

    assert severity_for_exception(tomorrow_policy, "pip", "requests", "UNPINNED_VERSION") == "INFO"
    assert severity_for_exception(_policy(), "pip", "requests", "UNPINNED_VERSION", default="CRITICAL") == "CRITICAL"


def test_git_scanner_handles_missing_gitmodules(tmp_path):
    assert GitScanner().scan(tmp_path, _policy()) == ([], [])


def test_git_scanner_reports_insecure_submodule_urls(tmp_path):
    (tmp_path / ".gitmodules").write_text(
        """
[submodule "safe"]
  path = safe
  url = https://example.test/safe.git
[submodule "bad"]
  path = bad
  url = http://example.test/bad.git
""".strip(),
        encoding="utf-8",
    )

    findings, components = GitScanner().scan(tmp_path, _policy())

    assert [finding.rule for finding in findings] == ["INSECURE_GIT_URL"]
    assert findings[0].severity == "CRITICAL"
    assert [component["name"] for component in components] == [
        "https://example.test/safe.git",
        "http://example.test/bad.git",
    ]


def test_package_manager_adapter_wraps_scanner_metadata_and_scan(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2\n", encoding="utf-8")
    adapter = PackageManagerAdapter(PipScanner())

    findings, components = adapter.scan(tmp_path, _policy())

    assert adapter.manager == "pip"
    assert adapter.supports_runtime_guard is True
    assert "requirements*.txt" in adapter.manifests
    assert "requirements.lock" in adapter.lockfiles
    assert [finding.rule for finding in findings] == ["UNPINNED_VERSION"]
    assert components[0]["name"] == "requests"


def test_default_package_manager_adapters_are_addressable_by_manager():
    adapters = adapters_by_manager()

    assert set(adapters) >= {"pip", "npm", "nuget", "git"}
    assert adapters["pip"] in DEFAULT_PACKAGE_MANAGER_ADAPTERS
    assert adapters["pip"].component_from_target(
        PackageTarget(manager="pip", name="requests", version="2.32.3")
    ) == {
        "type": "library",
        "manager": "pip",
        "name": "requests",
        "version": "2.32.3",
    }


def test_pip_scanner_requirements_pyproject_and_lockfiles(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "\n".join(
            [
                "# ignored",
                "--index-url https://evil.example/simple",
                "requests>=2",
                "blocked==1.0.0",
                "git+https://example/repo.git",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
dependencies = ["flask>=3", "blocked==1.0"]

[project.optional-dependencies]
dev = ["pytest==8.0"]
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        """
[[package]]
name = "locked"
version = "1.2.3"

[[package]]
name = "blocked"
version = "9.9.9"
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps({"default": {"pipfilepkg": {"version": "==1.0.0"}}, "develop": {"devpkg": {}}}),
        encoding="utf-8",
    )

    findings, components = PipScanner().scan(tmp_path, _policy())

    assert "UNTRUSTED_REGISTRY" in _rules(findings)
    assert "UNPINNED_VERSION" in _rules(findings)
    assert "DIRECT_URL" in _rules(findings)
    assert _rules(findings).count("DENYLIST") >= 2
    assert {component["name"] for component in components} >= {
        "requests",
        "blocked",
        "flask",
        "pytest",
        "locked",
        "pipfilepkg",
    }


def test_pip_scanner_invalid_project_and_lockfiles(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project", encoding="utf-8")
    (tmp_path / "uv.lock").write_text("[[package]\nname = 'broken'", encoding="utf-8")
    (tmp_path / "Pipfile.lock").write_text("{ invalid", encoding="utf-8")

    findings, _ = PipScanner().scan(tmp_path, _policy())

    assert "INVALID_PYPROJECT" in _rules(findings)
    assert "INVALID_UV_LOCK" in _rules(findings)
    assert "INVALID_PIPFILE_LOCK" in _rules(findings)


def test_npm_scanner_manifest_lockfiles_registry_and_extractors(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"lodash": "^4.17.21", "blocked": "1.0.0"},
                "devDependencies": {"crypto-stealer": "1.0.0"},
                "scripts": {"postinstall": "node install.js"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {"node_modules/pkg": {"name": "pkg", "version": "1.0.0"}},
                "dependencies": {"dep": {"version": "2.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "pnpm-lock.yaml").write_text(
        "packages:\n  /@scope/pkg@1.0.0:\n    version: 1.0.0\n  /plain@2.0.0:\n    version: 2.0.0\n",
        encoding="utf-8",
    )
    (tmp_path / "yarn.lock").write_text(
        '"left-pad@^1.3.0", "@scope/name@^2.0.0":\n  version "1.3.0"\n',
        encoding="utf-8",
    )
    (tmp_path / ".npmrc").write_text("registry=https://evil.example/\n", encoding="utf-8")

    findings, components = NpmScanner().scan(tmp_path, _policy())

    assert "FLOATING_VERSION" in _rules(findings)
    assert "DENYLIST" in _rules(findings)
    assert "SUSPICIOUS_NAME" in _rules(findings)
    assert "INSTALL_SCRIPT" in _rules(findings)
    assert "UNTRUSTED_REGISTRY" in _rules(findings)
    assert {component["name"] for component in components} >= {
        "lodash",
        "pkg",
        "dep",
        "@scope/pkg",
        "plain",
        "left-pad",
        "@scope/name",
    }


def test_npm_scanner_detects_alias_workspace_and_source_dependency_risks(tmp_path):
    workspace = tmp_path / "packages" / "app"
    workspace.mkdir(parents=True)
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "root",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "dependencies": {
                    "alias-lodash": "npm:lodash@^4.17.21",
                    "git-risk": "git+https://example.test/repo.git",
                    "tar-risk": "https://example.test/pkg-1.0.0.tgz",
                    "local-risk": "file:../local-risk",
                },
            }
        ),
        encoding="utf-8",
    )
    (workspace / "package.json").write_text(
        json.dumps({"name": "workspace-app", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {}}), encoding="utf-8")

    findings, components = NpmScanner().scan(tmp_path, _policy())

    assert "FLOATING_VERSION" in _rules(findings)
    assert _rules(findings).count("DIRECT_URL") == 2
    assert "LOCAL_PATH_DEPENDENCY" in _rules(findings)
    assert {component["name"] for component in components} >= {"lodash", "left-pad"}


def test_npm_scanner_dependency_helper_edges():
    scanner = NpmScanner()

    assert scanner._component_name_from_dependency("alias", "npm:@scope/pkg@1.2.3") == "@scope/pkg"
    assert scanner._component_name_from_dependency("alias", "npm:@scope/pkg") == "@scope/pkg"
    assert scanner._component_name_from_dependency("plain", "1.0.0") == "plain"
    assert scanner._is_floating_version("npm:@scope/pkg@~1.0.0")
    assert scanner._is_floating_version("npm:lodash@latest")
    assert not scanner._is_floating_version("npm:lodash@4.17.21")
    assert scanner._dependency_source_finding("tar-risk", "pkg-1.0.0.tgz", "package.json").rule == "DIRECT_URL"
    assert scanner._dependency_source_finding("safe", "1.0.0", "package.json") is None


def test_npm_scanner_missing_lockfile_allowed_registry_and_skipped_paths(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "root", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}}),
        encoding="utf-8",
    )
    node_modules = tmp_path / "node_modules" / "ignored"
    node_modules.mkdir(parents=True)
    (node_modules / "package.json").write_text(
        json.dumps({"name": "ignored", "version": "1.0.0", "dependencies": {"bad": "latest"}}),
        encoding="utf-8",
    )
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "package.json").write_text(
        json.dumps({"name": "ignored-example", "version": "1.0.0", "dependencies": {"bad": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / ".npmrc").write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")

    findings, components = NpmScanner().scan(
        tmp_path,
        _policy(require_lockfiles=True, exclude_paths=["examples/"]),
    )

    assert [finding.rule for finding in findings] == ["MISSING_LOCKFILE"]
    assert [component["name"] for component in components] == ["lodash"]


@pytest.mark.parametrize(
    ("filename", "content", "expected_rule"),
    [
        ("package.json", "{ invalid", "INVALID_MANIFEST"),
        ("package-lock.json", "{ invalid", "INVALID_PACKAGE_LOCK"),
        ("pnpm-lock.yaml", "[", "INVALID_PNPM_LOCK"),
    ],
)
def test_npm_scanner_invalid_json_and_yaml(tmp_path, filename, content, expected_rule):
    (tmp_path / filename).write_text(content, encoding="utf-8")

    findings, _ = NpmScanner().scan(tmp_path, _policy())

    assert expected_rule in _rules(findings)


def test_nuget_scanner_manifests_lock_registry_and_floating_versions(tmp_path):
    (tmp_path / "Demo.csproj").write_text(
        """
<Project>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.*" />
    <PackageReference Include="Range.Package" Version="[13.0.1,14.0.0)" />
    <PackageReference Include="blocked"><Version>1.0.0</Version></PackageReference>
  </ItemGroup>
</Project>
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "Directory.Packages.props").write_text(
        """
<Project>
  <ItemGroup>
    <PackageVersion Include="Central.Package" Version="1.0,2.0" />
  </ItemGroup>
</Project>
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "packages.config").write_text(
        '<packages><package id="Legacy.Package" version="*" /></packages>',
        encoding="utf-8",
    )
    (tmp_path / "packages.lock.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "net8.0": {
                        "Locked.Package": {"resolved": "1.2.3"},
                        "Requested.Package": {"requested": "2.0.0"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "NuGet.Config").write_text(
        '<configuration><packageSources><add key="evil" value="https://evil.example/v3/index.json" /></packageSources></configuration>',
        encoding="utf-8",
    )

    findings, components = NugetScanner().scan(tmp_path, _policy())

    assert "FLOATING_VERSION" in _rules(findings)
    assert "DENYLIST" in _rules(findings)
    assert "UNTRUSTED_REGISTRY" in _rules(findings)
    assert {component["name"] for component in components} >= {
        "Newtonsoft.Json",
        "Range.Package",
        "blocked",
        "Central.Package",
        "Legacy.Package",
        "Locked.Package",
        "Requested.Package",
    }


@pytest.mark.parametrize(
    ("filename", "content", "expected_rule"),
    [
        ("Broken.csproj", "<Project", "INVALID_CSPROJ"),
        ("Directory.Packages.props", "<Project", "INVALID_DIRECTORY_PACKAGES_PROPS"),
        ("packages.config", "<packages", "INVALID_PACKAGES_CONFIG"),
        ("packages.lock.json", "{ invalid", "INVALID_PACKAGES_LOCK"),
    ],
)
def test_nuget_scanner_invalid_files(tmp_path, filename, content, expected_rule):
    (tmp_path / filename).write_text(content, encoding="utf-8")

    findings, _ = NugetScanner().scan(tmp_path, _policy())

    assert expected_rule in _rules(findings)


def test_nuget_scanner_invalid_packages_lock_shape(tmp_path):
    (tmp_path / "packages.lock.json").write_text(json.dumps({"dependencies": []}), encoding="utf-8")

    findings, _ = NugetScanner().scan(tmp_path, _policy())

    assert "INVALID_PACKAGES_LOCK" in _rules(findings)
