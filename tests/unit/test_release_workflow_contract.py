from __future__ import annotations

import json
import re
from pathlib import Path

from scripts.release import create_release_manifest
from scripts.release.create_release_manifest import artifact_path, collect_files

ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-template.yml"
NPM_E2E_WORKFLOW = ROOT / ".github" / "workflows" / "e2e-npm.yml"
WORKFLOWS_DIR = ROOT / ".github" / "workflows"


def _release_workflow_text() -> str:
    return RELEASE_WORKFLOW.read_text(encoding="utf-8")


def _npm_e2e_workflow_text() -> str:
    return NPM_E2E_WORKFLOW.read_text(encoding="utf-8")


def _workflow_texts() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOWS_DIR.glob("*.yml"))
    }


def _job_block(text: str, job: str) -> str:
    match = re.search(rf"(?ms)^  {re.escape(job)}:\n.*?(?=^  [A-Za-z0-9_-]+:|\Z)", text)
    assert match is not None
    return match.group(0)


def test_release_publish_jobs_are_explicitly_gated_and_skippable():
    text = _release_workflow_text()

    for job in ("publish-pypi", "publish-npm", "publish-nuget"):
        block = _job_block(text, job)
        assert "if: ${{ startsWith(github.ref, 'refs/tags/v') || inputs.publish == 'true' }}" in block

    pypi_block = _job_block(text, "publish-pypi")
    assert "id-token: write" in pypi_block
    assert "environment:" in pypi_block
    assert "name: pypi" in pypi_block
    assert re.search(r"uses: pypa/gh-action-pypi-publish@[0-9a-f]{40} # release/v1", pypi_block)
    assert "packages-dir: dist/" in pypi_block
    assert "PYPI_API_TOKEN" not in pypi_block
    assert "twine upload" not in pypi_block

    assert "NPM_TOKEN is not configured. Skipping npm publish." in text
    assert "NUGET_API_KEY is not configured. Skipping NuGet publish." in text
    assert 'npm publish "$NPM_TARBALL" --access public --provenance' in text
    assert 'dotnet nuget push "dotnet-dist/*.nupkg"' in text


def test_release_dry_run_builds_artifacts_without_registry_publish():
    text = _release_workflow_text()

    preflight = _job_block(text, "preflight")
    release_manifest = _job_block(text, "release-manifest")
    attestation = _job_block(text, "attest-build-provenance")
    github_release = _job_block(text, "github-release")
    publish_pypi = _job_block(text, "publish-pypi")

    assert "if: ${{ inputs.publish == 'true' }}" not in preflight
    assert "if: ${{ inputs.publish == 'true' }}" not in release_manifest
    assert "if: ${{ inputs.publish == 'true' }}" not in attestation
    assert "if: ${{ inputs.publish == 'true' }}" not in github_release
    assert "startsWith(github.ref, 'refs/tags/v') || inputs.publish == 'true'" in attestation
    assert "startsWith(github.ref, 'refs/tags/v') || inputs.publish == 'true'" in github_release
    assert "startsWith(github.ref, 'refs/tags/v') || inputs.publish == 'true'" in publish_pypi


def test_release_dry_run_dispatch_uses_current_ref_until_publish_or_tag():
    text = _release_workflow_text()

    assert "inputs.publish == 'true' && inputs.release_version && format('v{0}', inputs.release_version) || github.ref" in text
    assert "body_path: RELEASE_NOTES_2026-06-21-0.5.1.md" in text


def test_release_attestation_and_github_release_include_all_artifact_classes():
    text = _release_workflow_text()

    for artifact_path in (
        "dist/*",
        "npm-dist/*",
        "dotnet-dist/*",
        "release-artifacts/release-manifest.json",
    ):
        assert artifact_path in text

    assert re.search(r"uses: actions/attest-build-provenance@[0-9a-f]{40} # v4", text)
    assert "attestations: write" in text
    assert re.search(r"uses: softprops/action-gh-release@[0-9a-f]{40} # v3", text)


def test_required_workflow_actions_are_pinned_to_full_shas():
    mutable_refs = []

    for workflow_name, text in _workflow_texts().items():
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = re.search(r"uses:\s+([^@\s]+)@([^\s#]+)", line)
            if not match:
                continue
            ref = match.group(2)
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                mutable_refs.append(f"{workflow_name}:{line_number}: {line.strip()}")

    assert mutable_refs == []


def test_npm_runtime_guard_workflow_uses_dedicated_e2e_scripts():
    text = _npm_e2e_workflow_text()
    runtime_block = _job_block(text, "runtime-guard")

    assert "if: github.event_name == 'workflow_dispatch'" not in runtime_block
    assert "continue-on-error: true" not in runtime_block
    assert "bash scripts/e2e/npm_guard_bash.sh" in runtime_block
    assert "./scripts/e2e/npm_guard_pwsh.ps1" in runtime_block
    assert "call scripts\\e2e\\npm_guard_cmd.bat" in runtime_block

    for script_name in ("npm_guard_bash.sh", "npm_guard_pwsh.ps1", "npm_guard_cmd.bat"):
        script_text = (ROOT / "scripts" / "e2e" / script_name).read_text(encoding="utf-8")
        assert "npm install lodash" in script_text
        assert "npm install lodash@4.17.21 --save-exact --ignore-scripts" in script_text
        assert "lodash" in script_text
        assert "4.17.21" in script_text
        assert "npm install --package-lock-only --ignore-scripts" in script_text
        assert "npm update lodash" in script_text
        assert "npm uninstall lodash" in script_text
        assert "postinstall" in script_text


def test_release_manifest_collects_python_npm_and_nuget_artifacts(tmp_path):
    paths = [
        tmp_path / "dist" / "safedeps-1.0.0.tar.gz",
        tmp_path / "dist" / "safedeps-1.0.0-py3-none-any.whl",
        tmp_path / "packages" / "npm-wrapper" / "jaydemks-safedeps-1.0.0.tgz",
        tmp_path / "artifacts" / "dotnet" / "SafeDeps.Tool.1.0.0.nupkg",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("artifact", encoding="utf-8")

    assert [artifact_path(tmp_path, path) for path in collect_files(tmp_path)] == [
        "artifacts/dotnet/SafeDeps.Tool.1.0.0.nupkg",
        "dist/safedeps-1.0.0-py3-none-any.whl",
        "dist/safedeps-1.0.0.tar.gz",
        "packages/npm-wrapper/jaydemks-safedeps-1.0.0.tgz",
    ]


def test_release_manifest_main_writes_checksums_and_posix_paths(tmp_path, monkeypatch):
    artifact = tmp_path / "dist" / "safedeps-1.0.0.tar.gz"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("artifact", encoding="utf-8")
    output = tmp_path / "release-artifacts" / "manifest.json"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        [
            "create_release_manifest.py",
            "--root",
            str(tmp_path),
            "--version",
            "1.0.0",
            "--output",
            str(output.relative_to(tmp_path)),
        ],
    )

    assert create_release_manifest.main() == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["version"] == "1.0.0"
    assert data["artifacts"] == [
        {
            "path": "dist/safedeps-1.0.0.tar.gz",
            "size": len("artifact"),
            "sha256": "c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c",
        }
    ]
