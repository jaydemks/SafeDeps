from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read_doc(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_claim_docs_track_blocking_workflows_and_versions():
    text = "\n".join(
        [
            read_doc("ROADMAP.md"),
            read_doc("docs/CI_INTEGRATION.md"),
            read_doc(".github/workflows/quality.yml"),
            read_doc(".github/workflows/e2e-pip.yml"),
            read_doc(".github/workflows/e2e-poetry.yml"),
        ]
    )

    for workflow in (
        "Quality",
        "E2E - pip Guard",
        "E2E - Poetry Lock Validation",
    ):
        assert workflow in text

    for version in ("23.3.2", "24.0", "24.3.1", "25.0.1"):
        assert version in text

    for version in ("1.7.1", "1.8.5", "2.0.1", "2.1.4", "2.2.1", "2.3.4", "2.4.1"):
        assert version in text


def test_public_docs_keep_unproven_claims_limited():
    text = "\n".join(
        [
            read_doc("ROADMAP.md"),
            read_doc("docs/COMPARISON.md"),
            read_doc("docs/ECOSYSTEM_SUPPORT.md"),
        ]
    )

    assert "public registry publishing until those areas have their own green, blocking evidence" in text
    assert "Trusted Publishing" in text
    assert "Runtime blocking for npm and NuGet must remain experimental" in text


def test_comparison_scopes_strongest_claims():
    text = read_doc("docs/COMPARISON.md")

    assert "tested local dependency policy gates" in text
    assert "Top Frontier Baseline" in text
    assert "private top-frontier baseline" in text
    assert "does not claim stable npm runtime protection" in text


def test_ecosystem_support_keeps_poetry_and_registry_claims_honest():
    text = read_doc("docs/ECOSYSTEM_SUPPORT.md")

    assert "| Poetry lockfiles | Supported | Not claimed | Stable for lockfile scan validation |" in text
    assert "This does not promote Poetry install/update runtime interception" in text
    assert "Runtime blocking for npm and NuGet must remain experimental" in text


def test_public_docs_do_not_link_private_comparison_artifacts():
    public_docs = [
        "README.md",
        "ROADMAP.md",
        "MAIN_ROADMAP.md",
        "RELEASE_NOTES_TEMPLATE.md",
        "docs/COMPARISON.md",
        "docs/ECOSYSTEM_SUPPORT.md",
    ]
    combined = "\n".join(read_doc(path) for path in public_docs)

    assert "PARITY.md" not in combined
