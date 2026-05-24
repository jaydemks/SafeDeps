# Release Notes - 2026-05-22

## Scope

First documentation hardening pass for open-source public distribution readiness and AI-pipeline workflow.

## Task Index

- T001 - Read and audit all Markdown docs.
- T002 - Consolidate install, usage, testing, and publishing docs into a single authoritative README.
- T003 - Upgrade roadmap to frontier-level milestone structure.
- T004 - Remove redundant Markdown files no longer needed as standalone docs.
- T005 - Establish release-notes discipline with indexed task tracking.

## Completed

### T001 - Markdown Audit

- Reviewed: `README.md`, `ROADMAP.md`, `TESTING.md`, `PUBLISHING.md`.
- Identified overlap and duplicated guidance across testing/publishing docs.

### T002 - README Consolidation

- Rewrote `README.md` to be the main source of truth.
- Added explicit install and publish guidance for:
  - Python / pip / PyPI
  - npm wrapper / npm registry
  - .NET tool publication path (planned, status declared)
- Added quickstart, policy example, verification workflow, and security scope section.

### T003 - Roadmap Upgrade

- Replaced roadmap with frontier-track milestones (`M1`..`M6`).
- Added clear definition-of-done criteria per milestone.
- Added execution rules for ordered, test-backed, documentation-aligned development.

### T004 - Documentation Cleanup

- Removed redundant docs:
  - `TESTING.md`
  - `PUBLISHING.md`
- Merged their useful content into `README.md`.

### T005 - Release Tracking Setup

- Created this release notes file with task index.
- Established convention: every future meaningful change must append/update release notes.

## Breaking Changes

- Documentation structure changed: standalone testing/publishing docs removed in favor of unified README.

## Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.
- F003: Add CI workflow that enforces scan + tests + artifact generation before release.

## Incremental Update (2026-05-22)

### Task Index Additions

- T006 - Create reusable release notes template.
- T007 - Align package versions and define a single versioning policy.

### Added

- Added `RELEASE_NOTES_TEMPLATE.md` with standard sections:
  - Scope
  - Task Index
  - Added/Changed/Fixed/Security
  - Breaking Changes
  - Verification
  - Follow-up Queue

### Changed

- Updated `pyproject.toml` version from `0.1.0` to `0.2.0` to align with:
  - `safedeps/__init__.py`
  - `packages/npm-wrapper/package.json`
- Added explicit versioning policy in `README.md`.

### Fixed

- Fixed release version mismatch between Python and npm distributions.

### Security

- Reduced release integrity risk caused by cross-package version drift.

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M3 slice - local vulnerability feed adapter)

### Task Index Additions

- T042 - Add local vulnerability feed adapter with severity normalization.

### Added

- New module:
  - `safedeps/vulnerability_intel.py`
- New local feed support:
  - `.safedeps/vuln-feed.json`
  - entry fields: `manager`, `package`, `id`, `severity`, `message`
- New finding rule:
  - `KNOWN_VULNERABILITY`
- Cross-source severity normalization to SafeDeps severity scale.

### Changed

- `scan` now ingests local vulnerability feed findings (when present) before baseline filtering/threshold evaluation.
- README updated with local vulnerability feed usage notes.
- Roadmap M3 status updated with feed adapter kickoff.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/vulnerability_intel.py safedeps/cli.py safedeps/policy.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added test:
  - `test_local_vulnerability_feed_adds_normalized_finding`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M3 kickoff - vulnerability baseline)

### Task Index Additions

- T041 - Add vulnerability baseline suppression mechanism.

### Added

- Baseline suppression support in scan pipeline:
  - default file: `.safedeps/vuln-baseline.json`
  - suppression list key: `suppress`
  - matching fields: `manager`, `rule`, `package`, `file`
- Stable finding fingerprinting in CLI for baseline matching.
- New policy fields:
  - `enable_vulnerability_baseline`
  - `vulnerability_baseline_file`

### Changed

- Scan now applies baseline filtering before threshold evaluation and report generation.
- README now documents vulnerability baseline support.
- Roadmap M3 status updated with baseline support kickoff.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py safedeps/policy.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added test:
  - `test_vulnerability_baseline_suppresses_matching_findings`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, exporter hardening)

### Task Index Additions

- T038 - Harden SARIF/CycloneDX/SPDX exporters with richer metadata.
- T039 - Deduplicate repeated components in CycloneDX/SPDX exports.

### Changed

- `cli.py` exporter improvements:
  - SARIF now includes tool semantic version and invocation success metadata.
  - CycloneDX now includes timestamp, serial number, tool version, and `bom-ref`.
  - SPDX now uses dynamic creation timestamp.
- CycloneDX/SPDX now deduplicate repeated components before writing output.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added test:
  - `test_sbom_exporters_deduplicate_same_component`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M4 slice - SPDX export)

### Task Index Additions

- T037 - Add SPDX JSON export support to `scan` command.

### Added

- New scan flag:
  - `--spdx <path>`
- SPDX (`SPDX-2.3`) export generation from collected components.
- SPDX package entries include purl external refs when manager metadata is available.

### Changed

- README scan examples now include SPDX usage.
- Roadmap M4 status updated with SPDX kickoff note.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added test:
  - `test_scan_writes_spdx_when_requested`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M4 slice - CycloneDX export)

### Task Index Additions

- T036 - Add CycloneDX JSON export support to `scan` command.

### Added

- New scan flag:
  - `--cyclonedx <path>`
- CycloneDX (`specVersion: 1.5`) export generation from collected components.
- Basic purl mapping by ecosystem (`npm`, `pypi`, `nuget`).

### Changed

- README scan examples now include CycloneDX usage.
- Roadmap M4 status updated with CycloneDX kickoff note.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added test:
  - `test_scan_writes_cyclonedx_when_requested`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M4 slice - SARIF export)

### Task Index Additions

- T035 - Add SARIF export support to `scan` command.

### Added

- New scan flag:
  - `--sarif <path>`
- SARIF generation (`2.1.0`) from scan findings:
  - rules catalog
  - severity mapping to SARIF levels
  - file locations when available

### Changed

- README scan examples now include SARIF usage.
- Roadmap M4 status updated with SARIF kickoff note.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added test:
  - `test_scan_writes_sarif_when_requested`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M2 slice - maintainer change detection)

### Task Index Additions

- T034 - Add maintainer change risk signal from metadata cache.

### Added

- New signal rule:
  - `MAINTAINER_CHANGE_RISK` (`MEDIUM`)
- New policy fields:
  - `enable_maintainer_change_checks`
  - `max_maintainer_changes_180d`

### Changed

- Integrated maintainer change signal in:
  - `pip_scanner.py`
  - `npm_scanner.py`
  - `nuget_scanner.py`
- Extended `metadata_signals.py` with maintainer-change evaluator.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/policy.py safedeps/scanners/metadata_signals.py safedeps/scanners/pip_scanner.py safedeps/scanners/npm_scanner.py safedeps/scanners/nuget_scanner.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added test:
  - `test_maintainer_change_signal_reports_medium_from_metadata_cache`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M2 operability - doctor baseline)

### Task Index Additions

- T033 - Add `safedeps doctor` command for setup/cache health validation.

### Added

- New CLI command:
  - `safedeps doctor [path]`
- Doctor checks:
  - presence of `.safedeps/`
  - presence and JSON validity of `.safedeps/policy.json`
  - JSON validity/shape of `.safedeps/metadata-cache.json` (when present)
  - warning when metadata cache is missing

### Changed

- README quickstart now includes `safedeps doctor .` command.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py tests/test_cli.py`
- Added tests:
  - `test_doctor_fails_without_safedeps_dir`
  - `test_doctor_passes_with_valid_policy_and_cache`
  - `test_doctor_fails_with_invalid_cache_json`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, packaging hardening for pip users)

### Task Index Additions

- T031 - Include required runtime dependency for pnpm lock parsing.
- T032 - Define official development dependency set for test execution.

### Changed

- Updated `pyproject.toml`:
  - added runtime dependency: `PyYAML>=6.0`
  - added optional dev extra: `.[dev]` with `pytest>=8.0`
- Updated `README.md` install section with:
  - `pip install .[dev]`

### Verification

- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M2 slice - age/churn signals)

### Task Index Additions

- T029 - Add metadata-based package age signal.
- T030 - Add metadata-based publisher churn signal.

### Added

- New module:
  - `safedeps/scanners/metadata_signals.py`
- New signal rules:
  - `PACKAGE_TOO_NEW` (`MEDIUM`)
  - `PUBLISHER_CHURN` (`MEDIUM`)
- Local offline metadata source support:
  - `.safedeps/metadata-cache.json`
- New policy fields:
  - `enable_package_age_checks`
  - `min_package_age_days`
  - `enable_publisher_churn_checks`
  - `max_publisher_changes_90d`

### Changed

- Integrated age/churn signal checks in:
  - `pip_scanner.py`
  - `npm_scanner.py`
  - `nuget_scanner.py`

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/policy.py safedeps/scanners/metadata_signals.py safedeps/scanners/pip_scanner.py safedeps/scanners/npm_scanner.py safedeps/scanners/nuget_scanner.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_package_age_signal_reports_medium_from_metadata_cache`
  - `test_publisher_churn_signal_reports_medium_from_metadata_cache`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M2 kickoff - typosquatting)

### Task Index Additions

- T027 - Add typosquatting risk detector module.
- T028 - Integrate typosquatting checks into pip/npm/nuget scanners with policy controls.

### Added

- New module:
  - `safedeps/scanners/typosquat.py`
- New finding rule:
  - `TYPOSQUATTING_RISK` (severity `MEDIUM`)
- New policy fields in `DEFAULT_POLICY`:
  - `enable_typosquat_detection` (default `true`)
  - `protected_packages` (seed list for high-value package names)

### Changed

- Typosquatting signal applied across:
  - `pip_scanner.py`
  - `npm_scanner.py`
  - `nuget_scanner.py`

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/policy.py safedeps/scanners/typosquat.py safedeps/scanners/pip_scanner.py safedeps/scanners/npm_scanner.py safedeps/scanners/nuget_scanner.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_typosquatting_risk_for_pip_dependency_reports_medium`
  - `test_typosquatting_risk_for_npm_dependency_reports_medium`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M1 closure sprint)

### Task Index Additions

- T025 - Add npm monorepo/workspace lockfile support for nested manifests.
- T026 - Add M1 closure status block to roadmap with completed/deferred split.

### Changed

- `NpmScanner` now scans lockfiles recursively instead of root-only:
  - `**/package-lock.json`
  - `**/pnpm-lock.yaml`
  - `**/yarn.lock`
- Lockfile presence validation is now manifest-aware:
  - each `package.json` is validated against lockfiles in its directory or parent workspace directories.
- Lockfile findings now use relative file paths (not only root-level filenames).

### Added

- Tests for workspace/monorepo lockfile behavior:
  - `test_monorepo_root_lockfile_covers_workspace_package`
  - `test_monorepo_workspace_without_lockfile_reports_missing`
- Roadmap section `M1 Closure For v0.2.x (2026-05-22)` in `ROADMAP.md`.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/scanners/npm_scanner.py tests/test_cli.py safedeps/cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, NuGet lockfile validation hardening)

### Task Index Additions

- T023 - Add `packages.lock.json` parsing in NuGet scanner.
- T024 - Add invalid NuGet lockfile detection and reporting.

### Added

- `NugetScanner` now parses `packages.lock.json` and extracts inventory from `dependencies`.
- Supports TFM-scoped dependency sets from lockfile structure.
- Adds parse/shape validation finding:
  - `INVALID_PACKAGES_LOCK`
- Applies `DENYLIST` checks to lockfile entries.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/scanners/nuget_scanner.py tests/test_cli.py safedeps/cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_packages_lock_json_denylist_fails`
  - `test_packages_lock_json_invalid_reports_high`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, codebase modularization + NuGet M1)

### Task Index Additions

- T020 - Refactor scanner architecture from single file to modular package.
- T021 - Add `Directory.Packages.props` NuGet scanning.
- T022 - Add `packages.config` NuGet scanning.

### Changed

- Replaced monolithic scanner file with modular structure:
  - `safedeps/scanners/base.py`
  - `safedeps/scanners/pip_scanner.py`
  - `safedeps/scanners/npm_scanner.py`
  - `safedeps/scanners/nuget_scanner.py`
  - `safedeps/scanners/git_scanner.py`
  - `safedeps/scanners/__init__.py`
- Removed old monolithic file:
  - `safedeps/scanners.py`
- Kept compatibility for existing imports by exporting `SCANNERS` (and optional `yaml`) from the new package `__init__`.

### Added

- NuGet parser support for `Directory.Packages.props`:
  - package inventory extraction
  - `DENYLIST` enforcement
  - `FLOATING_VERSION` checks
  - `INVALID_DIRECTORY_PACKAGES_PROPS` finding on parse failure
- NuGet parser support for `packages.config`:
  - package inventory extraction
  - `DENYLIST` enforcement
  - `FLOATING_VERSION` checks
  - `INVALID_PACKAGES_CONFIG` finding on parse failure

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py safedeps/scanners/__init__.py safedeps/scanners/base.py safedeps/scanners/pip_scanner.py safedeps/scanners/npm_scanner.py safedeps/scanners/nuget_scanner.py safedeps/scanners/git_scanner.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_directory_packages_props_denylist_fails`
  - `test_packages_config_denylist_fails`
  - `test_directory_packages_props_invalid_reports_high`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M1 yarn-lock parsing)

### Task Index Additions

- T019 - Add `yarn.lock` scanning for lockfile inventory and denylist enforcement.

### Added

- `NpmScanner` now parses `yarn.lock` (text-based parser, no extra dependencies).
- Extracts package names (including scoped packages) and resolved versions when present.
- Adds lockfile components to SBOM (`scope`: `yarn-lock`).
- Applies `DENYLIST` checks for each lockfile package entry.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/scanners.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_yarn_lock_denylist_fails`
  - `test_yarn_lock_scoped_denylist_fails`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M1 pnpm-lock parsing)

### Task Index Additions

- T017 - Add `pnpm-lock.yaml` scanning with optional YAML parser support.
- T018 - Add `pnpm-lock.yaml` parser-absent safe fallback and invalid lockfile handling.

### Added

- `NpmScanner` now attempts to parse `pnpm-lock.yaml`.
- Extracts package inventory from `packages` keys into SBOM components.
- Applies `DENYLIST` checks to pnpm lockfile packages.
- Adds parse/availability findings:
  - `PNPM_YAML_PARSER_MISSING` (LOW)
  - `INVALID_PNPM_LOCK` (HIGH)

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/scanners.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_pnpm_lock_denylist_or_parser_warning`
  - `test_pnpm_lock_invalid_reports_high_when_yaml_available`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M1 package-lock parsing)

### Task Index Additions

- T015 - Add `package-lock.json` scanning for npm lockfile inventory and denylist enforcement.
- T016 - Add invalid `package-lock.json` error reporting.

### Added

- `NpmScanner` now parses `package-lock.json`.
- Supports inventory extraction from:
  - `packages` (npm lockfile v2/v3 shape)
  - `dependencies` (legacy-compatible shape)
- Extracts components into SBOM with lockfile scopes.
- Applies `DENYLIST` checks to lockfile packages.
- Adds parse error finding:
  - `INVALID_PACKAGE_LOCK`

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/scanners.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_package_lock_denylist_fails`
  - `test_package_lock_invalid_reports_high`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M1 Pipfile.lock parsing)

### Task Index Additions

- T013 - Add `Pipfile.lock` scanning for Python lockfile inventory and denylist enforcement.
- T014 - Add invalid `Pipfile.lock` error reporting.

### Added

- `PipScanner` now parses `Pipfile.lock` JSON sections:
  - `default`
  - `develop`
- Extracts package inventory into SBOM components (`scope`: `pipfile-lock:<section>`).
- Applies `DENYLIST` checks to lockfile packages.
- Adds parse error finding:
  - `INVALID_PIPFILE_LOCK`

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/scanners.py tests/test_cli.py scripts/check_versions.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_pipfile_lock_denylist_fails`
  - `test_pipfile_lock_invalid_reports_high`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M1 lockfile parsing)

### Task Index Additions

- T011 - Add `poetry.lock` scanning for Python lockfile inventory and denylist enforcement.
- T012 - Add `uv.lock` scanning for Python lockfile inventory and denylist enforcement.

### Added

- `PipScanner` now parses TOML lockfiles:
  - `poetry.lock`
  - `uv.lock`
- Extracts package inventory into SBOM components (`scope`: `poetry-lock` / `uv-lock`).
- Applies `DENYLIST` checks to lockfile packages.
- Adds parse error findings:
  - `INVALID_POETRY_LOCK`
  - `INVALID_UV_LOCK`

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/scanners.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_poetry_lock_denylist_fails`
  - `test_uv_lock_denylist_fails`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M1 parser extension)

### Task Index Additions

- T010 - Add `pyproject.toml` dependency scanning for Python ecosystem.

### Added

- `PipScanner` now parses `pyproject.toml` via `tomllib`.
- Scans:
  - `project.dependencies`
  - `project.optional-dependencies`
- Applies existing policy rules on parsed dependencies:
  - `DENYLIST`
  - `UNPINNED_VERSION`
- Added parser error finding:
  - `INVALID_PYPROJECT`

### Changed

- Python lockfile requirement now triggers when any Python manifest is present:
  - `requirements*.txt` or
  - `pyproject.toml`

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/scanners.py tests/test_cli.py scripts/check_versions.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added tests:
  - `test_pyproject_unpinned_dependency_fails`
  - `test_pyproject_pinned_dependency_passes`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, F003)

### Task Index Additions

- T009 - Enforce ordered CI quality gate: version check, tests, scan, artifacts.

### Changed

- Updated `.github/workflows/safedeps.yml` CI pipeline:
  - install dependencies (`pip`, `pytest`, package)
  - run `python -m pytest -q`
  - run `safedeps scan . --fail-on HIGH`
  - upload `security-artifacts/` always

### Security

- CI now blocks merges on failing tests before dependency-policy scan, reducing false confidence from scan-only pipelines.

### Verification

- Local check executed: `python3 -m pytest -q`
- Local environment result: `No module named pytest` (tooling not installed locally).
- CI workflow now installs `pytest` explicitly, so pipeline execution is self-contained.

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, F004)

### Task Index Additions

- T008 - Implement automated cross-package version consistency check.

### Added

- Added `scripts/check_versions.py` to validate version alignment across:
  - `pyproject.toml`
  - `safedeps/__init__.py`
  - `packages/npm-wrapper/package.json`

### Changed

- Updated `.github/workflows/safedeps.yml` to run version consistency check before install/scan.
- Updated `README.md` versioning policy section with CI enforcement command.

### Fixed

- Closed follow-up item `F004` by adding an actual blocking CI gate.

### Security

- Prevents accidental release drift between package ecosystems, reducing supply-chain confusion risk.

### Verification

- Ran `python3 scripts/check_versions.py` locally.
- Result: `Version consistency check passed: 0.2.0`.

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.
- F003: Add CI workflow that enforces scan + tests + artifact generation before release.

## Incremental Update (2026-05-22, M4 slice - CI templates)

### Task Index Additions

- T040 - Add CI template examples for GitHub Actions, GitLab CI, and Azure Pipelines.

### Added

- New folder: `examples/ci/`
- New docs/template files:
  - `examples/ci/README.md`
  - `examples/ci/github/safedeps.yml`
  - `examples/ci/gitlab/.gitlab-ci.yml`
  - `examples/ci/azure/azure-pipelines.yml`
- Templates include scan execution and export of:
  - JSON report
  - SBOM-lite
  - SARIF
  - CycloneDX
  - SPDX

### Changed

- README now includes a dedicated `CI Templates` section.
- Roadmap M4 status updated to include CI template implementation.

### Verification

- Verified template files are present under `examples/ci/`.
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M3 slice - OSV-style local feed import)

### Task Index Additions

- T043 - Extend local vulnerability adapter with OSV-style feed ingestion.

### Added

- `vulnerability_intel.py` now supports `vulnerabilities_osv` entries in `.safedeps/vuln-feed.json`.
- OSV-like fields supported:
  - `id`
  - `summary`
  - `severity` (CVSS-style numeric mapping)
  - `affected[].package.ecosystem`
  - `affected[].package.name`
- Ecosystem normalization mapping included (`PyPI` -> `pip`).

### Changed

- Severity normalization now includes CVSS score translation for OSV-style records.
- README local feed section updated with OSV-style note.
- Roadmap M3 status updated with OSV-style ingestion progress.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/vulnerability_intel.py safedeps/cli.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added test:
  - `test_local_osv_feed_adds_vulnerability_finding`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M3 baseline expiration enforcement)

### Task Index Additions

- T044 - Add expiration-aware suppression for vulnerability baseline entries.

### Changed

- Baseline suppression now supports optional `expires` date per suppression entry.
- Expired suppression entries are ignored automatically during scan.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py tests/test_cli.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Added test:
  - `test_vulnerability_baseline_expired_entry_does_not_suppress`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M4 slice - artifact validation tests)

### Task Index Additions

- T045 - Add automated artifact validation script and CI enforcement step.

### Added

- New script:
  - `scripts/validate_artifacts.py`
- Script validates presence and minimal schema shape for:
  - `safedeps-report.json`
  - `safedeps-sbom.json`
  - `safedeps.sarif`
  - `safedeps.cdx.json`
  - `safedeps.spdx.json`

### Changed

- GitHub workflow now runs:
  - full scan with SARIF/CycloneDX/SPDX outputs
  - artifact validation script before artifact upload
- README now includes artifact validator usage command.
- Roadmap M4 status updated with artifact validation coverage.

### Verification

- Static validation:
  - `python3 -m py_compile scripts/validate_artifacts.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M6 kickoff - release automation template)

### Task Index Additions

- T046 - Add release preflight validation script.
- T047 - Add GitHub release workflow template.
- T048 - Add release process documentation.
- T049 - Align README with release automation template usage.

### Added

- New script:
  - `scripts/release/preflight.py`
- New workflow:
  - `.github/workflows/release-template.yml`
- New process document:
  - `docs/release/RELEASE_PROCESS.md`

### Changed

- Roadmap M6 now includes a concrete kickoff status with delivered artifacts and remaining closure items.
- README now documents release preflight command and release workflow template usage.

### Verification

- Static validation:
  - `python3 -m py_compile scripts/release/preflight.py`
- Version guard validation:
  - `python3 scripts/check_versions.py`
  - Result: `Version consistency check passed: 0.2.0`
- Preflight execution:
  - `python3 scripts/release/preflight.py`
  - Result: `preflight: PASS version=0.2.0`

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M5 slice - UX commands completion pass)

### Task Index Additions

- T050 - Add `safedeps explain <finding_rule>` command.
- T051 - Add `safedeps baseline` command to generate suppression file from scan report.
- T052 - Add `safedeps approve --expires YYYY-MM-DD` command for expiring suppressions.
- T053 - Add CLI tests for baseline/approve/explain behavior.
- T054 - Update roadmap and README with M5 command usage.

### Added

- New CLI command:
  - `safedeps explain <finding_rule>`
- New CLI command:
  - `safedeps baseline <path> [--report ...] [--output ...]`
- New CLI command:
  - `safedeps approve <path> --manager ... --rule ... --expires YYYY-MM-DD [--package ...] [--file ...]`

### Changed

- Roadmap M5 now includes concrete progress status.
- README quickstart/docs now include usage examples for explain/baseline/approve.
- Added tests in `tests/test_cli.py` for:
  - baseline generation
  - expiring approval write
  - explain known rule
  - invalid approval date rejection.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py tests/test_cli.py`
- Smoke checks:
  - `safedeps baseline` path with generated report -> baseline file created
  - `safedeps approve ... --expires 2026-12-31` -> suppression entry written
  - `safedeps explain FLOATING_VERSION` -> explanation returned
- Note:
  - `pytest` is not available in this local environment (`No module named pytest`), so full test suite execution is deferred to CI or a dev env with `pip install .[dev]`.

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M5 slice - HTML report and pre-commit)

### Task Index Additions

- T055 - Add HTML report export to `scan` command.
- T056 - Add repository pre-commit integration config.
- T057 - Add CLI test coverage for HTML export.
- T058 - Update README and roadmap with new M5 capabilities.

### Added

- New scan output option:
  - `--html <path>` to generate a readable HTML report.
- New repository config:
  - `.pre-commit-config.yaml` with local SafeDeps hook.

### Changed

- README now documents HTML export usage and pre-commit setup.
- Roadmap M5 status updated: HTML + pre-commit marked as implemented.
- Test suite now includes `test_scan_writes_html_when_requested`.

### Verification

- Static validation:
  - `python3 -m py_compile safedeps/cli.py tests/test_cli.py`
- Smoke checks:
  - `safedeps scan ... --html security-artifacts/safedeps-report.html` writes report file.
  - HTML output contains title and status summary.
- Note:
  - Full `pytest` execution remains deferred in this local environment without `pytest` installed.

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M5 slice - output stability tests)

### Task Index Additions

- T059 - Add output stability tests for `explain` command.
- T060 - Add output stability tests for `doctor` command.
- T061 - Update roadmap M5 status for golden coverage progress.

### Added

- New CLI output stability tests in `tests/test_cli.py`:
  - `test_explain_output_stability`
  - `test_explain_unknown_rule_output_stability`
  - `test_doctor_output_stability_without_safedeps_dir`

### Changed

- Roadmap M5 status now explicitly tracks partial golden-output coverage and remaining commands to cover.

### Verification

- Static validation:
  - `python3 -m py_compile tests/test_cli.py`
- Note:
  - full `pytest` run remains deferred in this environment without `pytest` installed.

### Follow-up Queue

- F001: Implement and publish .NET global tool wrapper.

## Incremental Update (2026-05-22, M6 slice - .NET global tool and release pipeline)

### Task Index Additions

- T062 - Implement `.NET global tool` wrapper project.
- T063 - Extend release preflight with `.NET tool` version consistency checks.
- T064 - Extend release workflow template with `.NET nupkg` artifact build.
- T065 - Update README and release process docs for `.NET tool` install/build/publish.

### Added

- New project:
  - `packages/dotnet-tool/SafeDeps.Tool.csproj`
  - `packages/dotnet-tool/Program.cs`
- New release workflow job:
  - `build-dotnet-tool` in `.github/workflows/release-template.yml`
  - outputs `dotnet-tool-nupkg` artifact.

### Changed

- `scripts/release/preflight.py` now validates `.NET tool` package version alignment with:
  - `pyproject.toml`
  - `safedeps/__init__.py`
  - `packages/npm-wrapper/package.json`
  - `packages/dotnet-tool/SafeDeps.Tool.csproj`
- Release process documentation now includes NuGet pack/push steps.
- README `.NET` install/publish instructions updated to implemented wrapper flow.

### Verification

- Static validation:
  - `python3 -m py_compile scripts/release/preflight.py`
- Runtime checks:
  - `python3 scripts/check_versions.py`
  - `python3 scripts/release/preflight.py`

### Follow-up Queue

- F001: Activate trusted publishing/signing stages (PyPI/npm/NuGet) in release automation.

## Incremental Update (2026-05-22, M6 slice - trusted publishing gates)

### Task Index Additions

- T066 - Add gated publish controls to release workflow (`publish=true/false`).
- T067 - Add PyPI trusted publishing stage (OIDC).
- T068 - Add npm provenance publish stage.
- T069 - Add conditional NuGet publish stage (`NUGET_API_KEY`).
- T070 - Align README/release process docs with gated publish workflow.

### Changed

- `.github/workflows/release-template.yml` now includes:
  - workflow input `publish` (default `false`)
  - `publish-pypi` job with `id-token: write`
  - `publish-npm` job with provenance publish command
  - `publish-nuget` job guarded by secret presence
- `docs/release/RELEASE_PROCESS.md` now documents release controls and publish behavior.
- README release automation section updated with .NET artifact and publish gate notes.
- Roadmap M6 updated to reflect trusted-publish stage implementation and remaining hardening.

### Verification

- Static validation:
  - `python3 -m py_compile scripts/release/preflight.py`
- Runtime checks:
  - `python3 scripts/release/preflight.py` (version/file consistency gate still passes)

### Follow-up Queue

- F001: Configure production environments/secrets and enable signed/tagged release closure.

## Incremental Update (2026-05-23, hardening - strict preflight and broader golden coverage)

### Task Index Additions

- T071 - Add strict preflight expected-version gate.
- T072 - Add strict preflight tag/version gate for publish runs.
- T073 - Wire release workflow to pass expected version and tag gate on publish.
- T074 - Extend CLI output stability tests for `scan`, `baseline`, and `approve`.
- T075 - Align roadmap/docs with new hardening behavior.

### Changed

- `scripts/release/preflight.py` now supports:
  - `--expected-version`
  - `--require-tag` (expects `GITHUB_REF_NAME=vX.Y.Z` aligned with package version)
- `.github/workflows/release-template.yml` now passes workflow `release_version` into preflight and enables `--require-tag` when `publish=true`.
- Roadmap M5/M6 status updated for expanded golden coverage and stricter release gates.
- README and release process docs updated with strict preflight command examples.

### Added

- New output-stability tests in `tests/test_cli.py`:
  - `test_baseline_output_stability`
  - `test_approve_output_stability`
  - `test_scan_summary_output_stability_for_clean_project`

### Verification

- Static validation:
  - `python3 -m py_compile scripts/release/preflight.py tests/test_cli.py safedeps/cli.py`
- Runtime checks:
  - `python3 scripts/release/preflight.py --expected-version 0.2.0`
  - `python3 scripts/release/preflight.py --expected-version 9.9.9` (expected fail path)

### Follow-up Queue

- F001: Configure production environments/secrets and enable signed/tagged release closure.

## Incremental Update (2026-05-23, M6 hardening - artifact integrity manifest)

### Task Index Additions

- T076 - Extend cross-distribution version gate to include .NET tool package version in main CI check.
- T077 - Add release artifact manifest generator with SHA256 checksums.
- T078 - Add release workflow job to build/upload checksum manifest and gate publish jobs on it.
- T079 - Extend preflight required files with release-manifest generator script.
- T080 - Align release documentation and roadmap with artifact integrity stage.

### Added

- New script:
  - `scripts/release/create_release_manifest.py`
- New release workflow job:
  - `release-manifest` in `.github/workflows/release-template.yml`
  - output artifact: `release-manifest/release-artifacts/release-manifest.json`

### Changed

- `scripts/check_versions.py` now validates:
  - `packages/dotnet-tool/SafeDeps.Tool.csproj` `PackageVersion`
- `scripts/release/preflight.py` now requires:
  - `scripts/release/create_release_manifest.py`
- Publish jobs now depend on successful `release-manifest` generation.

### Verification

- Static validation:
  - `python3 -m py_compile scripts/check_versions.py scripts/release/preflight.py scripts/release/create_release_manifest.py`
- Runtime checks:
  - `python3 scripts/check_versions.py`
  - `python3 scripts/release/preflight.py --expected-version 0.2.0`
  - `python3 scripts/release/create_release_manifest.py --version 0.2.0`

### Follow-up Queue

- F001: Configure production environments/secrets and enable signed/tagged release closure.

## Incremental Update (2026-05-23, M5/M6 closure pass - golden fixture + tag release automation)

### Task Index Additions

- T081 - Add fixture-driven golden snapshot test for multi-finding `scan` output.
- T082 - Add tag-triggered (`v*`) release execution path in workflow.
- T083 - Add GitHub Release publication step with artifacts and checksum manifest.
- T084 - Add build provenance attestation stage for release artifacts.
- T085 - Align roadmap and release docs with tagged release automation behavior.

### Added

- New golden fixture:
  - `tests/golden/scan_bad_project_snapshot.txt`
- New test:
  - `test_scan_bad_project_fixture_snapshot` in `tests/test_cli.py`
- Release workflow capabilities in `.github/workflows/release-template.yml`:
  - trigger on push tags `v*`
  - `attest-build-provenance` job
  - `github-release` job (artifact attachments + generated release notes)

### Changed

- Preflight invocation in release workflow now derives expected version from:
  - `inputs.release_version` (manual workflow_dispatch)
  - `GITHUB_REF_NAME` tag without `v` prefix (tag workflow path)
- README / release process / roadmap updated with tag-driven release closure details.

### Verification

- Static validation:
  - `python3 -m py_compile tests/test_cli.py scripts/release/preflight.py`
- Runtime checks:
  - `python3 -c "from safedeps.cli import main; import sys; sys.exit(main(['scan','examples/bad-project','--out','.tmp-security','--fail-on','HIGH']))"` (for snapshot baseline)
  - `python3 scripts/release/preflight.py --expected-version 0.2.0`

### Follow-up Queue

- F001: Configure production environments/secrets and enable final production publish/signing posture.

## Incremental Update (2026-05-23, docs closure - simple usage and compatibility guidance)

### Task Index Additions

- T086 - Add simple top-level README section explaining what SafeDeps does.
- T087 - Add practical usage scenarios in README.
- T088 - Add explicit "when useful / when not needed or not compatible" guidance in README.
- T089 - Correct README .NET install section label from planned to current state.
- T090 - Update roadmap baseline date and add repo-completion note.

### Changed

- README now includes:
  - `What It Is (Simple)`
  - `Typical Scenarios`
  - `When It Is Useful`
  - `When It Is Not Needed or Not Compatible`
- ROADMAP baseline updated to current date and explicit repo-completion note added.

### Verification

- Manual documentation consistency pass across:
  - `README.md`
  - `ROADMAP.md`
  - `docs/release/RELEASE_PROCESS.md`

### Follow-up Queue

- F001: Configure production environments/secrets and enable final production publish/signing posture.
