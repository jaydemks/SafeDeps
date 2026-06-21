# SafeDeps 0.4.0 Beta Preview - Release Notes (2026-06-18)

## Scope

Beta Preview stabilization release focused on trust signals, release discipline, documentation, CI gates, and test coverage before adding new product features.

SafeDeps 0.4.0 intentionally does not expand ecosystem promises. Python/pip remains the primary stable path; npm and NuGet remain documented as limited/experimental until their compatibility matrix is green.

## Task Index

- T001 - Verify last published remote tag and align release version after `v0.3.4`.
- T002 - Add the priority rule to `MAIN_ROADMAP.md`: no new features until CI, tests, threat model, docs, and release gates are solid.
- T003 - Add developer quality tooling and a single `make checks` release gate.
- T004 - Add GitHub quality/security workflow scaffolding and Dependabot configuration.
- T005 - Add initial trust documentation: known limitations, threat model, support matrix, policy, bypass/approvals, CI integration, architecture, security, and contributing docs.
- T006 - Add package manifest controls so release artifacts include docs, tests, examples, and packaged assets intentionally.
- T007 - Add targeted tests for reports, runtime selection, runtime guard behavior, guard hooks/state, dependency actions, exceptions, approvals, baseline generation, UI state, CLI facades, UI server startup behavior, UI handler GET/POST workflows, guard autostart state transitions, and runtime pip guard blocking paths.
- T008 - Raise the coverage gate from no enforceable project gate to 80%.
- T009 - Align Python, npm wrapper, and .NET wrapper versions to `0.4.0`.

## Changed

- Stabilization release with stronger CI, test, documentation, threat-model and release gates before new features.
- Raised automated quality gate with Ruff, mypy, pytest coverage, package build, twine check and CLI smoke checks.
- Added targeted unit coverage for policy reports, runtime guard state, dependency actions, exceptions, approvals, baseline, CLI facades, UI server startup behavior, UI handler GET/POST workflows, guard autostart state transitions, and runtime pip guard blocking paths.
- Added UI server edge-case coverage for Windows shortcut generation, setup/guard POST workflows, and broken client writes.
- Hardened guard state and runtime guard edge cases for unwritable PowerShell profile paths, Windows PATH normalization, SafeDeps specifier parsing, PEP 508 direct references, and case-insensitive official repository checks.
- Added a dedicated pip guard e2e workflow across Bash on Ubuntu/macOS, PowerShell on Windows, and CMD on Windows.
- Tightened npm and NuGet wording so scanning remains supported but runtime protection is explicitly experimental until dedicated e2e matrices are green.
- Documented the Trusted Publishing and release attestation gate: scaffolded release workflow paths must be validated before they become release guarantees.
- Aligned the release workflow so tag-created GitHub Releases wait for NuGet publishing and build provenance attestation jobs.
- Updated package metadata to modern license fields and build requirements.
- Aligned the legacy CI release preflight with `0.4.0`.
- Moved the published `0.3.4` release note into `release-notes/old/` so the repository root contains only the active `0.4.0` release note.

## Fixed

- Fixed missing imports used by report generation and runtime guard state helpers.
- Reduced release-risk blind spots around dependency mutation rollback, approval/baseline handling, and CLI facade wiring.
- Fixed guard wrapper generation so virtualenv Python executables are preserved instead of being resolved to the underlying system interpreter.
- Added focused regression coverage for scan pipeline report output, npm audit handling, Git remote detection, and interpreter guard hook installation/removal.
- Added focused regression coverage for local vulnerability feeds, OSV-style records, CVSS severity mapping, and metadata age/churn/maintainer-change signals.
- Added batch scanner regression coverage for pip, npm, and NuGet manifests, lockfiles, invalid files, registry allowlists, denylist hits, floating versions, install scripts, and package-manager lock parsers.
- Added focused dependency-management and dependency UI coverage for policy quick updates, auto-version resolution, npm actions, rollback failures, post-change CRITICAL checks, runtime dependency collection, dependency table rendering, and pip guard panel states.
- Added guard-state hardening coverage for corrupt state files, legacy auto-guard keys, Windows registry PATH/AutoRun helpers, PowerShell profile failures, forced autoguard resync, and cleanup preserving auto-guard state.
- Expanded the pip guard e2e workflow with representative pip versions, `requirements.txt` blocking/allowing, project-scope outside-root behavior, project-venv guard coverage, and parity across Bash, PowerShell, and CMD for core install cases.
- Added npm validation workflow coverage for scan failures/passes, lockfile-backed `npm ci`, and diagnostic experimental runtime guard checks.
- Added NuGet validation workflow coverage for floating/range PackageReference failures, pinned PackageReference passes, and `Directory.Packages.props` scan coverage.
- Fixed NuGet range detection so bracketed range versions such as `[13.0.1,14.0.0)` are treated as floating/range findings.
- Hardened `safedeps doctor` so it reports policy shape problems, metadata cache shape/date issues, missing lockfiles, inactive guard state, and missing npm/.NET toolchains when relevant.
- Expanded `safedeps explain` coverage for emitted finding rules and added explicit `Fix:` guidance to the main rule explanations.
- Hardened the runtime pip guard so requirement/constraint files, `--flag=value` options, and direct URL/VCS runtime installs are handled before pip mutates dependencies.
- Aligned generated Bash, PowerShell, and CMD pip wrappers so direct URL/VCS installs are blocked consistently.
- Added deterministic report stability coverage for SARIF, CycloneDX, SPDX, and HTML outputs.
- Added lightweight policy schema v1 validation without introducing a `jsonschema` dependency.
- Reused policy schema validation in `safedeps doctor` so malformed policy values produce actionable errors.
- Added a 90-second README quickstart and a comparison document for clearer positioning against adjacent tools.
- Added scan-supported Python, Node, and .NET example documentation and packaged the new example README/lockfile/project files.
- Documented the current CI matrix status across OS, Python, shell, pip, npm, NuGet, and security workflows.
- Added an explicit reporter registry and centralized scan output writer for JSON, SARIF, CycloneDX, SPDX, and HTML artifacts.
- Extracted shared supply-chain signal finding collection for typosquat, package age, publisher churn, and maintainer-change checks.
- Added a compatible `PackageTarget` core model and scanner metadata for manifests, lockfiles, and runtime-guard capability.
- Extracted guard wrapper and activation-file installation into a dedicated guard backend module with focused regression tests.
- Added a verifier interface and default supply-chain signal verifier, then routed pip/npm/NuGet scanner signal checks through that verifier pipeline.
- Added a package-manager adapter layer and routed the scan pipeline through default adapters instead of directly iterating raw scanners.
- Extracted CLI parser construction into a dedicated parser module so the CLI entrypoint is reduced to command dispatch.

## Security

- Added a first threat model and documented what SafeDeps does not guarantee.
- Added policy, bypass, approval, and CI integration documentation.
- Added security workflow scaffolding for CodeQL, dependency review, and OpenSSF Scorecard.
- Added Dependabot configuration for dependency hygiene.
- Documented that CodeQL, Dependency Review, OpenSSF Scorecard, Dependabot, and SARIF upload are present while Trusted Publishing and attestations remain release-gated.
- Added a maintainer pre-release review checklist for the final human review before commit, tag, or publishing.

## Breaking Changes

- None expected for CLI users.

## Verification

- `git ls-remote --tags origin` confirmed latest published tag is `v0.3.4`.
- `.venv/bin/python -m pytest tests/unit/test_exceptions.py tests/unit/test_dependency_actions.py -q` passed.
- `.venv/bin/python -m pytest tests/unit/test_cli_commands.py -q` passed.
- `.venv/bin/python -m pytest tests/unit/test_ui_server.py -q` passed: 14 tests.
- `.venv/bin/python -m pytest tests/test_cli.py::test_cleanup_guard_install_disables_auto_guard tests/test_cli.py::test_cleanup_guard_install_can_preserve_auto_guard_for_setup -q` passed.
- `.venv/bin/python -m pytest tests/unit/test_guard_state.py tests/unit/test_runtime_guard.py -q` passed: 43 tests.
- `.venv/bin/python -m pytest tests/test_cli.py::test_setup_generates_strict_project_guard_wrappers -q` passed.
- `.venv/bin/python -m pytest tests/unit/test_policy.py tests/unit/test_reports.py -q` passed.
- `.venv/bin/python -m pytest tests/unit/test_guard_repo.py tests/unit/test_guard_hooks.py tests/unit/test_scan.py -q` passed: 15 tests.
- `.venv/bin/python -m pytest tests/unit/test_vulnerability_intel.py tests/unit/test_metadata_signals.py -q` passed: 11 tests.
- `.venv/bin/python -m pytest tests/unit/test_scanners.py -q` passed: 12 tests.
- Workflow YAML parse check passed for all `.github/workflows/*.yml`.
- `.venv/bin/python scripts/release/preflight.py --expected-version 0.4.0` passed.
- `.venv/bin/python scripts/check_versions.py` passed.
- Local activated-shell e2e block check passed for unpinned `pip install six` and `python -m pip install six`.
- `.venv/bin/python -m pytest --cov=safedeps --cov-report=term-missing --cov-report=xml` passed: 314 tests, 91.38% coverage.
- Workflow YAML parse check passed after expanding `.github/workflows/e2e-pip.yml`.
- `.venv/bin/python scripts/release/preflight.py --expected-version 0.4.0` passed after expanding `.github/workflows/e2e-pip.yml`.
- `.venv/bin/python -m pytest tests/unit/test_scanners.py --cov=safedeps.scanners.nuget_scanner --cov=safedeps.scanners.npm_scanner --cov-report=term-missing --cov-fail-under=0` passed after the NuGet range fix.
- `.venv/bin/python -m pytest tests/unit/test_doctor.py tests/test_cli.py::test_doctor_fails_without_safedeps_dir tests/test_cli.py::test_doctor_passes_with_valid_policy_and_cache tests/test_cli.py::test_doctor_fails_with_invalid_cache_json tests/test_cli.py::test_doctor_output_stability_without_safedeps_dir --cov=safedeps.doctor --cov-report=term-missing --cov-fail-under=0` passed.
- `.venv/bin/python -m pytest tests/unit/test_exceptions.py tests/test_cli.py::test_explain_command_known_rule_ok tests/test_cli.py::test_explain_output_stability tests/test_cli.py::test_explain_unknown_rule_output_stability --cov=safedeps.exceptions --cov=safedeps.constants --cov-report=term-missing --cov-fail-under=0` passed.
- `.venv/bin/python -m pytest tests/unit/test_runtime_guard.py tests/test_cli.py::test_runtime_guard_blocks_direct_python_m_pip_unpinned_install tests/test_cli.py::test_runtime_guard_allows_out_of_scope_project_direct_python_m_pip tests/test_cli.py::test_runtime_guard_allows_direct_python_when_auto_guard_off tests/test_cli.py::test_runtime_guard_pth_line_targets_project_and_interpreter tests/test_cli.py::test_setup_generates_strict_project_guard_wrappers --cov=safedeps.runtime_guard --cov=safedeps.guard_hooks --cov=safedeps.guard --cov-report=term-missing --cov-fail-under=0` passed.
- `.venv/bin/python -m pytest tests/unit/test_reports.py tests/unit/test_scan.py tests/test_cli.py::test_setup_generates_strict_project_guard_wrappers -q` passed.
- `.venv/bin/python -m pytest tests/unit/test_policy.py tests/unit/test_doctor.py tests/test_cli.py::test_doctor_fails_without_safedeps_dir tests/test_cli.py::test_doctor_passes_with_valid_policy_and_cache tests/test_cli.py::test_doctor_fails_with_invalid_cache_json tests/test_cli.py::test_doctor_output_stability_without_safedeps_dir -q` passed.
- `.venv/bin/python -m ruff check safedeps/policy.py safedeps/doctor.py tests/unit/test_policy.py tests/unit/test_doctor.py` passed.
- Workflow YAML parse check passed for all `.github/workflows/*.yml` after documenting matrix status.
- `.venv/bin/python -m safedeps.cli scan examples/safe-project --fail-on HIGH --out /tmp/safedeps-safe-example` passed with 0 findings.
- `.venv/bin/python -m safedeps.cli scan examples/bad-project --fail-on HIGH --out /tmp/safedeps-bad-example` failed as expected with 13 findings.
- `python3 -m json.tool examples/safe-project/package-lock.json` and `python3 -m json.tool examples/safe-project/packages.lock.json` passed.
- `.venv/bin/python -m pytest tests/unit/test_reports.py tests/unit/test_scan.py tests/unit/test_metadata_signals.py tests/unit/test_scanners.py -q` passed.
- `.venv/bin/python -m ruff check safedeps/reports.py safedeps/scan.py safedeps/scanners/metadata_signals.py safedeps/scanners/pip_scanner.py safedeps/scanners/npm_scanner.py safedeps/scanners/nuget_scanner.py tests/unit/test_reports.py tests/unit/test_scan.py tests/unit/test_metadata_signals.py tests/unit/test_scanners.py` passed.
- `.venv/bin/python -m pytest tests/unit/test_scanners.py tests/unit/test_metadata_signals.py tests/unit/test_reports.py tests/unit/test_scan.py -q` passed after adding `PackageTarget` and scanner metadata.
- `.venv/bin/python -m ruff check safedeps/models.py safedeps/scanners/base.py safedeps/scanners/git_scanner.py safedeps/scanners/pip_scanner.py safedeps/scanners/npm_scanner.py safedeps/scanners/nuget_scanner.py safedeps/scanners/metadata_signals.py safedeps/reports.py safedeps/scan.py tests/unit/test_scanners.py tests/unit/test_metadata_signals.py tests/unit/test_reports.py tests/unit/test_scan.py` passed.
- Synthetic local npm/NuGet scan scenarios passed for floating-fail and pinned-pass cases.
- `.venv/bin/python -m pytest tests/unit/test_guard_backend.py tests/test_cli.py::test_setup_generates_strict_project_guard_wrappers tests/test_cli.py::test_setup_windows_keeps_cmd_bin_free_of_extensionless_wrappers -q` passed.
- `make checks PYTHON=.venv/bin/python` passed with 316 tests, 91.45% coverage, package build, twine check, and CLI smoke checks after extracting the guard backend install layer.
- `.venv/bin/python -m pytest tests/unit/test_verifiers.py tests/unit/test_metadata_signals.py tests/unit/test_scanners.py -q` passed after adding the verifier interface.
- `.venv/bin/python -m ruff check safedeps/verifiers.py safedeps/scanners/metadata_signals.py safedeps/scanners/pip_scanner.py safedeps/scanners/npm_scanner.py safedeps/scanners/nuget_scanner.py tests/unit/test_verifiers.py tests/unit/test_metadata_signals.py tests/unit/test_scanners.py` passed.
- `make checks PYTHON=.venv/bin/python` passed with 319 tests, 91.51% coverage, package build, twine check, and CLI smoke checks after routing scanner signal checks through the verifier pipeline.
- `.venv/bin/python -m pytest tests/unit/test_scan.py tests/unit/test_scanners.py -q` passed after adding the package-manager adapter layer.
- `.venv/bin/python -m ruff check safedeps/package_managers.py safedeps/scan.py tests/unit/test_scan.py tests/unit/test_scanners.py` passed.
- `make checks PYTHON=.venv/bin/python` passed with 321 tests, 91.60% coverage, package build, twine check, and CLI smoke checks after routing the scan pipeline through package-manager adapters.
- `.venv/bin/python -m pytest tests/unit/test_cli_parser.py tests/unit/test_cli_commands.py tests/test_cli.py::test_version_commands tests/test_cli.py::test_bad_project_fails tests/test_cli.py::test_scan_summary_output_stability_for_clean_project -q` passed after extracting CLI parser construction.
- `.venv/bin/python -m ruff check safedeps/cli.py safedeps/cli_parser.py tests/unit/test_cli_parser.py tests/unit/test_cli_commands.py` passed.
- `make checks PYTHON=.venv/bin/python` passed with 324 tests, 91.61% coverage, package build, twine check, and CLI smoke checks after the CLI parser extraction.
- Added `docs/maintainers/PRE_RELEASE_REVIEW.md` to guide the final manual review before tag/publish.
- Final local review smoke passed in WSL and native Windows PowerShell: help command works, safe fixture passes, and bad fixture blocks with 13 findings.
- Manual UI smoke passed for the core fixture path; browser-level UI automation remains tracked as post-0.4 work.
- `make checks PYTHON=.venv/bin/python` passed with Ruff, mypy, pytest coverage gate 80, package build, twine check, and CLI smoke checks.
- Latest local stabilization pass passed; build and coverage artifacts were cleaned afterward.

## Follow-up Queue

- F001 - Done: added remaining `ui_server.py` edge-case tests for Windows shortcut generation, setup/guard POST paths, and broken client writes.
- F002 - Done: hardened `guard_state.py` and runtime guard edge cases.
- F003 - Done for pip: added real OS/shell pip guard e2e workflow beyond the initial quality/security workflow scaffolding.
- F004 - Done: npm/NuGet runtime protection remains explicitly experimental until e2e matrix coverage exists.
- F005 - Done: release attestations / Trusted Publishing remain gated until the release workflow is fully validated.
- F006 - Done: final local stabilization pass is green; Git commit/tag/release remain deferred.
- F007 - Done: isolated guard wrapper and activation-file installation behind a tested guard backend module.
- F008 - Done: added a verifier interface and routed common supply-chain signal checks through it.
- F009 - Done: added package-manager adapters and routed the scan pipeline through them.
- F010 - Done: extracted CLI parser construction so the CLI entrypoint is a thinner dispatcher.
- F011 - Done: added final maintainer pre-release review guide and clarified non-blocking post-0.4 backlog.
