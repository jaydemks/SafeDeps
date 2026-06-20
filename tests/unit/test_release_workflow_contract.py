from __future__ import annotations

import re
from pathlib import Path

from scripts.release.create_release_manifest import collect_files

ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-template.yml"


def _release_workflow_text() -> str:
    return RELEASE_WORKFLOW.read_text(encoding="utf-8")


def _job_block(text: str, job: str) -> str:
    match = re.search(rf"(?ms)^  {re.escape(job)}:\n.*?(?=^  [A-Za-z0-9_-]+:|\Z)", text)
    assert match is not None
    return match.group(0)


def test_release_publish_jobs_are_explicitly_gated_and_skippable():
    text = _release_workflow_text()

    for job in ("publish-pypi", "publish-npm", "publish-nuget"):
        block = _job_block(text, job)
        assert "if: ${{ inputs.publish == 'true' }}" in block

    assert "PYPI_API_TOKEN is not configured. Skipping PyPI publish." in text
    assert "NPM_TOKEN is not configured. Skipping npm publish." in text
    assert "NUGET_API_KEY is not configured. Skipping NuGet publish." in text
    assert "python -m twine upload" in text
    assert 'npm publish "$NPM_TARBALL" --access public --provenance' in text
    assert 'dotnet nuget push "dotnet-dist/*.nupkg"' in text


def test_release_attestation_and_github_release_include_all_artifact_classes():
    text = _release_workflow_text()

    for artifact_path in (
        "dist/*",
        "npm-dist/*",
        "dotnet-dist/*",
        "release-artifacts/release-manifest.json",
    ):
        assert artifact_path in text

    assert "uses: actions/attest-build-provenance@v4" in text
    assert "attestations: write" in text
    assert "uses: softprops/action-gh-release@v3" in text


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

    assert [str(path.relative_to(tmp_path)) for path in collect_files(tmp_path)] == [
        "artifacts/dotnet/SafeDeps.Tool.1.0.0.nupkg",
        "dist/safedeps-1.0.0-py3-none-any.whl",
        "dist/safedeps-1.0.0.tar.gz",
        "packages/npm-wrapper/jaydemks-safedeps-1.0.0.tgz",
    ]
