# SafeDeps Roadmap (Frontier Track)

## Mission

Build SafeDeps into a frontier-level, open-source dependency security gate that any developer can adopt quickly across ecosystems, locally and in CI.

## Current Baseline (as of 2026-05-23)

- Python CLI core is available.
- npm wrapper package exists.
- .NET wrapper package exists (`packages/dotnet-tool`).
- Core checks are functional for common unsafe dependency patterns.

## Milestone M1: Engine Completeness

- Python:
  - `pyproject.toml`
  - `poetry.lock`
  - `uv.lock`
  - `Pipfile.lock`
  - hash enforcement with `--require-hashes`
- npm:
  - `package-lock.json`
  - `pnpm-lock.yaml`
  - `yarn.lock`
  - workspace/monorepo support
- NuGet:
  - `Directory.Packages.props`
  - `packages.config`
  - central package management
  - lockfile validation
- Containers/CI:
  - Dockerfile and Compose dependency extraction
  - GitHub Actions workflow dependency scanning

Definition of done:

- Parser coverage tests for each format.
- Deterministic findings across Linux/macOS/Windows test matrix.

### M1 Closure For v0.2.x (2026-05-22)

Completed in this cycle:

- Python parsers: `pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile.lock`.
- npm parsers: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`.
- npm workspace/monorepo lockfile resolution across nested `package.json`.
- NuGet parsers: `.csproj`, `Directory.Packages.props`, `packages.config`, `packages.lock.json`.
- CI baseline quality gates (version consistency + tests + scan + artifacts).

Deferred from M1 to next cycles:

- Python hash enforcement with `--require-hashes`.
- Dockerfile and Docker Compose dependency extraction.
- Dedicated GitHub Actions workflow-dependency parsing (beyond CI pipeline usage).
- Cross-OS deterministic matrix execution evidence.

## Milestone M2: Supply-Chain Intelligence

- Typosquatting signals.
- Package age and publish churn checks.
- Maintainer/publisher change detection.
- Trusted source model and metadata cache.
- Malicious package feed integration.
- Signature/hash verification where supported.
- Strict offline mode.

Definition of done:

- Low false-positive baseline on fixture corpus.
- Policy controls available for each signal.

### M2 Status (Kickoff 2026-05-22)

- Implemented first intelligence signal:
  - typosquatting risk detection (`TYPOSQUATTING_RISK`) for pip/npm/nuget package names.
- Implemented vulnerability baseline suppression support (`.safedeps/vuln-baseline.json`) with stable finding fingerprint matching.
- Implemented local vulnerability feed adapter (`.safedeps/vuln-feed.json`) with severity normalization.
- Extended local vulnerability feed adapter with OSV-style record ingestion (`vulnerabilities_osv`).
- Implemented second intelligence signal set (offline-first):
  - package age risk (`PACKAGE_TOO_NEW`) from local metadata cache
  - publisher churn risk (`PUBLISHER_CHURN`) from local metadata cache
- Implemented maintainer/publisher change detection (offline-first):
  - maintainer transfer/change risk (`MAINTAINER_CHANGE_RISK`) from local metadata cache
- Added policy controls:
  - `enable_typosquat_detection`
  - `protected_packages`
  - `enable_package_age_checks`
  - `min_package_age_days`
  - `enable_publisher_churn_checks`
  - `max_publisher_changes_90d`
  - `enable_maintainer_change_checks`
  - `max_maintainer_changes_180d`

## Milestone M3: Vulnerability Correlation

- OSV.dev integration.
- GitHub Advisory integration.
- NuGet vulnerability endpoint integration.
- npm audit normalization.
- pip-audit integration.
- Vulnerability baseline and expiring allowlist.

Definition of done:

- Unified severity model.
- Reproducible scan output with stable IDs.

## Milestone M4: CI and Compliance Outputs

- Official GitHub Action.
- GitLab and Azure templates.
- SARIF export.
- CycloneDX SBOM export.
- SPDX SBOM export.
- Signed release artifacts and provenance (SLSA-oriented).

Definition of done:

- End-to-end CI examples in `examples/ci`.
- Artifact validation tests.

### M4 Status (Kickoff 2026-05-22)

- Implemented initial SARIF export support from CLI scan via `--sarif`.
- Implemented initial CycloneDX JSON export support from CLI scan via `--cyclonedx`.
- Implemented initial SPDX JSON export support from CLI scan via `--spdx`.
- Hardened report exporters with component deduplication and richer metadata.
- Implemented CI templates in `examples/ci/` for GitHub/GitLab/Azure.
- Added automated artifact structure validation (`scripts/validate_artifacts.py`) in CI.

## Milestone M5: Developer UX

- HTML report.
- `safedeps explain <finding>`.
- `safedeps approve --expires YYYY-MM-DD`.
- `safedeps doctor`.
- `safedeps baseline`.
- Pre-commit integration.

Definition of done:

- Each UX command documented with examples.
- Golden tests for command output stability.

### M5 Status (Progress 2026-05-22)

- Implemented commands:
  - `safedeps doctor <path>`
  - `safedeps explain <finding_rule>`
  - `safedeps baseline <path> [--report ...] [--output ...]`
  - `safedeps approve <path> --manager ... --rule ... --expires YYYY-MM-DD`
- Implemented outputs/integration:
  - HTML report export via `safedeps scan --html ...`
  - repository pre-commit hook integration via `.pre-commit-config.yaml`
- Implemented test stability coverage:
  - command output stability tests for `doctor` and `explain`.
- Extended golden output coverage:
  - output stability tests for `scan`, `baseline`, and `approve`.
- Remaining to complete M5:
  - optional fixture-driven golden snapshots for larger multi-finding scan outputs.

## Milestone M6: Distribution and Adoption

- PyPI publication pipeline.
- npm trusted publishing pipeline.
- .NET global tool package and NuGet publication pipeline.
- Versioning/release automation and changelog discipline.

Definition of done:

- Public install works for `pip`, `npm`, and `dotnet`.
- Signed/tagged release process fully automated.

### M6 Status (Kickoff 2026-05-22)

- Added release preflight script:
  - `scripts/release/preflight.py`
  - validates cross-package version alignment and required release files.
- Added GitHub release workflow template:
  - `.github/workflows/release-template.yml`
  - preflight + Python build artifact + npm wrapper artifact.
- Added release process documentation:
  - `docs/release/RELEASE_PROCESS.md`
- Implemented .NET global tool wrapper:
  - `packages/dotnet-tool/SafeDeps.Tool.csproj`
  - `packages/dotnet-tool/Program.cs`
- Added .NET package build job to release workflow template:
  - outputs `.nupkg` artifact for NuGet publish stage.
- Added gated publish stages in release workflow template:
  - `publish-pypi` (OIDC trusted publishing)
  - `publish-npm` (provenance publish)
  - `publish-nuget` (conditional on `NUGET_API_KEY`)
- Added stricter release preflight gates:
  - `--expected-version` alignment with workflow input
  - `--require-tag` validation for publish runs (`vX.Y.Z`)
- Added release artifact integrity manifest stage:
  - deterministic SHA256 manifest for Python/npm/NuGet release outputs.
- Added tag-driven release closure automation:
  - trigger on `v*` tags
  - build provenance attestation
  - GitHub Release creation with attached artifacts + manifest.
- Remaining to complete M6:
  - production secret/environment wiring for publish jobs
  - NuGet package signing hardening in pipeline.

### Repo Completion Note (2026-05-23)

- Code and workflow implementation in this repository is effectively complete for the planned frontier track.
- Remaining items are external operational setup:
  - production secrets/environment configuration in GitHub
  - final NuGet signing posture
  - final full verification pass across release environments.

## Execution Rules

- All work must be incremental, ordered, and test-backed.
- Documentation must stay aligned to implemented behavior.
- Release notes must be updated on every meaningful change.
