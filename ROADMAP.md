# SafeDeps Roadmap

This file tracks work after the `v0.5.0` Beta Preview release.

`MAIN_ROADMAP.md` is the authoritative record for the long stabilization push that brought SafeDeps to the current pre-release state. This file should stay focused on future work only, so old completed items are not repeated as active TODOs.

## Current Baseline

Status after the `v0.5.1` Beta Preview:

- `v0.5.1` Beta Preview is published to PyPI and GitHub Releases.
- Local gate is green: `347` tests, `91.89%` coverage, package build, `twine check`, and CLI smoke.
- Architecture checklist is complete: CLI parser, scan pipeline, package-manager adapters, verifier interface, reporter registry, guard backend install layer, policy schema validation.
- Python/pip is the primary stable runtime guard path and is covered by blocking Linux, macOS, Windows PowerShell, and Windows CMD e2e jobs.
- Poetry lockfile scanning is validated across a required version matrix.
- npm and NuGet scan support are validated, while runtime protection remains limited or experimental unless explicitly documented otherwise.
- Local UI smoke has been manually validated from the native Windows side for the core Python/safe/bad fixture path.
- PyPI `0.5.1` is published through Trusted Publishing/OIDC; npm and NuGet packages are built as release assets but are not promoted as public-registry install channels yet.
- GitHub Release assets and build provenance exist for `v0.5.1`; npm provenance publishing, NuGet registry publishing, npm runtime protection, and NuGet runtime protection remain future validation work.
- Honest claim status: SafeDeps has strong repository, CI, documentation, and tested Python/pip evidence. It is still a Beta Preview until release trust, package-intelligence depth, npm/NuGet runtime matrices, and multi-release maturity are stronger.

## Next Strategic Target

Goal: move from a credible Beta Preview to a production-grade dependency firewall that clears the private top-frontier quality bar, without broadening public claims before the evidence exists.

Primary gaps to close:

1. Release trust: PyPI Trusted Publishing/OIDC, documented provenance, complete artifact attestation checks, and pinned GitHub Actions.
2. Package intelligence: OSV ingestion, local advisory datasets, suspicious package heuristics, package-age and maintainer-change signals, and deterministic offline fixtures.
3. Runtime depth: broader pip matrix plus blocking npm and NuGet runtime guard e2e coverage before runtime claims change.
4. Ecosystem depth: npm workspaces, aliases, tarballs, git dependencies, local paths, private registries; NuGet source mapping, private feeds, lockfiles, transitive packages.
5. Maturity: multiple consecutive green releases with no hidden failing jobs, no broad `continue-on-error`, and no claim drift between README, docs, release notes, and workflows.
6. Coverage hardening: move from high coverage to deliberate 100% coverage module by module, prioritizing security-critical and newly changed code first.

Suggested release ladder:

- `0.5.1`: release trust hardening. Enable/verify PyPI Trusted Publishing, pin GitHub Actions by SHA, and keep public claims scoped.
- `0.5.2`: package intelligence expansion. Add OSV/local advisory ingestion and richer malicious-package heuristics with deterministic tests.
- `0.5.3`: npm runtime truth work. Promote npm runtime guard only where blocking e2e matrices prove it.
- `0.5.4`: NuGet runtime truth work. Validate .NET package-source behavior, private feeds, lockfiles, and runtime guard feasibility.
- `0.6.0`: production-grade Beta/RC only if release trust, intelligence, npm/NuGet evidence, and maturity gates are all green.

Do not advance package versions at the start of a local hardening cycle. Change version files only when the next release scope is verified and the final release is ready.

### 0.5.1 Completed: Release Trust Hardening

Status: completed after PyPI Trusted Publishing/OIDC, release workflow SHA pinning, local contract tests, and GitHub Actions validation.

- [x] Configure PyPI Trusted Publishing/OIDC for the release workflow.
- [x] Remove the PyPI API-token/Twine fallback from the release workflow.
- [x] Pin third-party GitHub Actions to full commit SHAs, while keeping version comments for maintainability.
- [x] Add contract tests so token-based PyPI publishing cannot silently return.
- [x] Add contract tests so required workflows cannot silently return to mutable action refs.
- [x] Verify build provenance covers every release asset class listed in `release-manifest.json`.
- [x] Document exactly what the attestations prove and what they do not prove.
- [x] Run a non-publishing release dry-run and one real patch release to prove the PyPI Trusted Publishing path.

### 0.5.2 Completed: Package Intelligence Expansion

Status: completed after local gates and GitHub Actions validation. Additional coverage hardening raised `safedeps/vulnerability_intel.py`, `safedeps/policy.py`, `safedeps/reports.py`, `safedeps/scanners/base.py`, and `safedeps/scanners/git_scanner.py` to `100.00%` line and branch coverage.

- [x] Add OSV advisory ingestion behind deterministic local fixtures.
- [x] Add a normalized advisory model shared by pip, npm, NuGet, and local vulnerability feeds.
- [x] Match OSV-style affected version ranges with `introduced`, `fixed`, and `last_affected` events.
- [x] Preserve advisory aliases, references, component versions, and file hints in findings.
- [x] Add package age, maintainer-change, repository-link, and download/metadata anomaly signals where data is available.
- [x] Add malicious-package fixture datasets that are safe, synthetic, and deterministic.
- [x] Add policy controls for metadata-risk thresholds and advisory severities.
- [x] Keep online checks optional; offline deterministic checks must remain the release gate.
- [x] Raise the new local advisory intelligence module to `100.00%` line and branch coverage.
- [x] Raise policy loading and schema validation to `100.00%` line and branch coverage.
- [x] Raise report generation, baseline filtering, and scan summary output to `100.00%` line and branch coverage.
- [x] Raise scanner base helpers to `100.00%` line and branch coverage, including normalized `exclude_paths` handling.
- [x] Raise Git submodule scanning to `100.00%` line and branch coverage.
- [x] Verify GitHub Actions after push.

### 0.5.3 In Progress: npm Runtime Truth Work

Status: local workflow structure and dedicated npm runtime guard e2e scripts added. Keep npm runtime claims experimental until the matrix is green without broad `continue-on-error`.

- [ ] Decide exact supported npm versions and OS/shell combinations.
- [x] Extract npm runtime guard e2e coverage into dedicated Bash, PowerShell, and CMD scripts.
- [x] Add runtime script coverage for unpinned install block, pinned install allow, lifecycle-script block, and uninstall block.
- [x] Extend generated npm guard wrappers to block guarded `npm uninstall` operations.
- [x] Add workflow contract tests so npm runtime e2e logic stays script-based and explicit.
- [ ] Add blocking npm runtime e2e coverage for install, uninstall, update, package-lock, and lifecycle-script cases.
- [ ] Add coverage for workspaces, aliases, git dependencies, tarball URLs, and local path dependencies.
- [ ] Add registry/source policy tests for default registry, custom registry, and untrusted registry behavior.
- [ ] Keep npm runtime claims experimental until the matrix is green without broad `continue-on-error`.

### 0.5.4 Planned: NuGet Runtime Truth Work

Status: planned. Goal: decide whether NuGet stays scan-first or gains a stable runtime guard claim.

- [ ] Validate package-source behavior for `NuGet.Config`, source mapping, and private feeds.
- [ ] Add lockfile and transitive package tests for representative SDK versions.
- [ ] Add e2e coverage for `dotnet add package`, restore, floating versions, and untrusted sources where feasible.
- [ ] Decide and document whether runtime interception is supported or whether NuGet remains scan/CI policy only.
- [ ] Keep NuGet runtime claims experimental until the supported scope is proven by blocking e2e jobs.

### 0.6.0 Target: Production-Grade Evidence

Status: aspirational target, not guaranteed. Cut `0.6.0` only when SafeDeps has enough evidence to claim a meaningfully stronger production posture.

- [ ] At least one release-trust path is proven without API-token-only PyPI publishing.
- [ ] Required workflows use pinned action SHAs or an explicitly documented exception process.
- [ ] Package intelligence covers local advisories, OSV-style advisories, and metadata-risk signals with deterministic tests.
- [ ] npm and NuGet support claims are either proven by blocking runtime matrices or explicitly kept scan-only/experimental.
- [ ] Release notes, README, ecosystem support docs, and comparison docs all describe the same tested scope.
- [ ] At least two consecutive patch releases complete without hidden failing jobs or claim corrections after publication.
- [ ] Reach deliberate `100%` project coverage, or document any excluded line as intentionally untestable with a specific reason.

## Completed Or Superseded By v0.4.0

The following old roadmap themes have already been absorbed by `v0.4.0` and should not be treated as open work here:

- core test expansion and coverage gate;
- `make checks` release gate;
- Ruff, mypy, pytest coverage, build, `twine check`, and CLI smoke;
- CI quality/security scaffolding;
- OS/Python/shell/package-manager workflow matrix;
- threat model, limitations, policy, bypass/approval, ecosystem support, comparison, CI integration, release process, and contribution docs;
- release notes and version alignment for `0.4.0`;
- CLI parser extraction and thinner command dispatch;
- package-manager adapter layer;
- verifier interface and supply-chain signal verifier pipeline;
- report output registry;
- guard backend install layer;
- pip runtime guard hardening for the main supported paths;
- npm and NuGet scan validation workflows.

## Completed Post-v0.4 Milestones

The following sections are historical proof for how SafeDeps reached `v0.5.0`. They are kept for traceability, not as active TODOs.

### 0.4.1 Completed: CI Truth Hardening

Status: completed on `main` after the post-`v0.4.0` hardening commits. Keep `v0.4.0` unchanged until a future release is intentionally cut.

- Stable CI gates are now truthfully blocking instead of green because of broad `continue-on-error` masking.
- Windows e2e failures were fixed rather than hidden, including PowerShell, CMD, and pip guard shell-wrapper paths.
- `e2e-pip.yml` is promoted from diagnostic behavior to required validation for the supported pip guard paths.
- GitHub Actions were updated away from deprecated Node 20 action versions.
- npm and NuGet runtime/publishing claims remain deliberately limited until their own validation work is complete.

### 0.4.1 Local Work Plan

- [x] Inventory every `continue-on-error` and classify it as stable-required or diagnostic.
- [x] Reproduce the failing Windows/pip/e2e behavior locally or from GitHub logs before changing workflow policy.
- [x] Fix the failure first, then remove or narrow `continue-on-error`.
- Keep npm/NuGet runtime and registry publishing diagnostic/experimental until tested independently.
- Run local gates before any commit: `make checks`, version preflight, package build, `twine check`, and representative CLI/UI smoke.

### 0.4.2 Completed: pip Guard Compatibility Expansion

Status: completed after GitHub Actions validation. Focus: make Python/pip coverage strong enough to support stronger scoped claims without broadening ecosystem claims prematurely.

- [x] Add required e2e coverage for constraints files.
- [x] Add required e2e coverage for editable local installs.
- [x] Add required e2e coverage for local path installs.
- [x] Add required e2e coverage for direct URL installs where practical in CI.
- [x] Add explicit `--index-url` runtime behavior tests.
- [x] Add explicit `--extra-index-url` runtime behavior tests.
- [x] Add required `pip download` source-policy coverage for direct URLs and untrusted extra indexes.
- [x] Expand the pip-version matrix after the new behavior cases are green: `latest`, `23.3.2`, `24.0`, `24.3.1`, and `25.0.1` across the Bash Linux/macOS guard matrix.
- [x] Add combined `pip install -r requirements.txt -c constraints.txt` coverage.
- [x] Add required `pip uninstall` block coverage.
- [x] Add explicit global-scope runtime guard coverage outside the configured project root.
- Consider a wider Python-version-by-pip-version grid only if CI duration remains acceptable.

### 0.4.2 Cleanup: E2E Structure Refactor

Status: completed before `0.4.3`.

- [x] Extract Bash pip guard e2e behavior into `scripts/e2e/pip_guard_bash.sh`.
- [x] Extract PowerShell pip guard e2e behavior into `scripts/e2e/pip_guard_pwsh.ps1`.
- [x] Extract CMD pip guard e2e behavior into `scripts/e2e/pip_guard_cmd.bat`.
- [x] Keep `.github/workflows/e2e-pip.yml` focused on checkout, Python/pip matrix setup, and calling the e2e scripts.
- Keep future e2e workflows human-readable: named scripts, named test sections, no large inline shell blocks unless the logic is truly one-off.

### 0.4.3 Completed: Static Analysis Hardening

Status: completed locally after passing `make checks`; verify GitHub Actions after push.

- [x] Remove `ignore_errors = true` from mypy.
- [x] Expand Ruff from syntax-only checks to unused imports, redefinitions, unused variables, exception chaining, and sorted public exports.
- [x] Add import sorting, pyupgrade, and simplify Ruff gates with passing fixes.
- [x] Add comprehensions, pathlib, pie, and return-style Ruff gates with passing fixes.
- [x] Add naming Ruff gate and stricter mypy warnings for redundant casts, unused ignores, implicit optionals, and equality checks.
- Keep line-length, broad pylint-style rules, try/raise style, unused-argument cleanup, and deeper refactors as separate passing steps.

### 0.4.4 Completed: Poetry And Release-Trust Validation

Status: completed locally after passing `make checks`; verify GitHub Actions after push.

- [x] Add required Poetry lock scan e2e workflow across Poetry `1.7.1`, `1.8.5`, `2.0.1`, `2.1.4`, `2.2.1`, `2.3.4`, and `2.4.1`.
- [x] Validate SafeDeps scans a real `poetry lock` output as safe when no policy violation exists.
- [x] Validate SafeDeps reports denylist findings from real `poetry.lock` output.
- [x] Add static release workflow contract tests for artifact manifest, publish-token fallbacks, and attestation subject paths.
- [x] Validate release manifest generation writes deterministic POSIX artifact paths and SHA256 checksums.
- [x] Validate dry-run release workflow behavior builds artifacts without registry publish jobs.
- Keep PyPI Trusted Publishing, npm provenance, and NuGet publishing claims limited until real release workflow runs prove them.

### 0.4.5 Completed: Claim Evidence And Release Readiness

Status: completed after local gates and GitHub Actions validation. Package version files stayed at `0.4.0` until the final `0.5.0` release preparation.

- [x] Document supported-scope evidence for the tested SafeDeps policy-gate paths without naming private benchmark targets in public docs.
- [x] Keep comparison claims aligned with the tested support scope and private top-frontier baseline.
- [x] Update ecosystem support to include Poetry lockfile scan validation without promoting Poetry runtime interception.
- [x] Add documentation claim tests so future wording cannot silently overpromise Trusted Publishing, npm runtime protection, NuGet runtime protection, or public registry publishing.
- [x] Verify local gates after this evidence-pack update: `345` tests, `91.89%` coverage, package build, `twine check`, and CLI smoke.
- [x] Verify GitHub Actions after push.
- [x] Decide next release target: `0.5.0`, with version files unchanged until final release preparation.

### 0.5.0 Completed: Beta Preview Release

Status: completed after local gates, GitHub Actions validation, release dry-run, `v0.5.0` tag publish, PyPI publication, and GitHub Release verification.

- [x] Bump Python, npm wrapper, and .NET tool package versions to `0.5.0`.
- [x] Update legacy CI release preflight to expect `0.5.0`.
- [x] Prepare `0.5.0` Beta Preview release notes with scoped claims and follow-up limits.
- [x] Move the published `0.4.0` release note into `release-notes/old/`.
- [x] Run local version/preflight checks for `0.5.0`.
- [x] Run final local quality gate for `0.5.0`: `347` tests, `91.89%` coverage, package build, `twine check`, and CLI smoke.
- [x] Verify GitHub Actions after the final pre-tag validation push.
- [x] Run release workflow dry-run with `publish=false`.
- [x] Create tag and release only after the dry-run is green.
- [x] Verify PyPI `0.5.0` availability and GitHub Release `v0.5.0` assets.

## Post-v0.4 Backlog

These items are intentionally not blockers for `v0.4.0`.

### 0. Claim Hardening Work

Status: achieved for the tested SafeDeps policy-gate scope; keep the remaining bullets as future expansion and claim-hardening work.

- Remove or narrow `continue-on-error`:
  - `e2e-pip.yml` stable jobs must become required once Windows and shell failures are fixed;
  - `quality.yml` Windows failures must be fixed or split into an explicitly diagnostic job;
  - `security.yml` diagnostic checks must be separated from required security gates;
  - npm runtime guard jobs should stay experimental until they are designed as required support.
- Add a broad pip compatibility matrix:
  - representative pip versions across supported Python versions;
  - install, uninstall, requirements, constraints, local path, editable, direct URL, and index-url cases;
  - Windows PowerShell, Windows CMD, Bash on Ubuntu, and Bash on macOS where relevant.
- Add Poetry compatibility work:
  - supported Poetry versions;
  - lockfile scan behavior;
  - install/update command behavior if runtime protection is claimed later.
- Tighten static analysis:
  - remove `ignore_errors = true` from mypy only after targeted modules are typed enough;
  - expand Ruff rules beyond `E9` and `F821` in small steps;
  - keep each tightening paired with fixes so CI remains useful instead of noisy.
- Harden release trust:
  - validate PyPI Trusted Publishing or keep API-token publishing documented as fallback;
  - keep npm and NuGet unpublished until registry credentials, package identity, provenance, and dry-run/real publish flow are verified;
  - verify attestations cover all release assets and document exactly what they prove.
- Track progress with a clear claim ladder:
  - Beta credible: achieved by `v0.4.0`;
  - Strong scoped evidence: achieved for the tested Python/pip and Poetry lockfile policy-gate scope;
  - Broader SafeDeps evidence: achieved for the tested policy-gate scope through local UI, policy workflow, cross-ecosystem scan support, agent-oriented dependency gates, and clearer limitation docs;
  - Stable broad ecosystem claims: not claimed until release signing, Trusted Publishing, npm runtime protection, NuGet runtime protection, and public registry publishing have their own green, blocking evidence.

### A. Python/pip Guard Hardening

- Add or expand coverage for:
  - `pip install -c constraints.txt -r requirements.txt`;
  - `pip install .`;
  - `pip install -e .`;
  - direct wheel URLs;
  - local path installs;
  - explicit `--index-url` / `--extra-index-url` runtime behavior;
  - global scope runtime behavior;
  - auto guard on/off transitions.
- Keep Python/pip as the reference quality bar for other ecosystems.

### B. npm Truth Release Work

- Decide the exact npm support level by tested command/version/OS.
- Expand coverage for:
  - workspaces;
  - alias packages such as `alias@npm:real-package`;
  - git dependencies;
  - tarball URLs;
  - local path dependencies.
- Keep npm runtime guard language experimental until the matrix is no longer diagnostic/experimental.

### C. NuGet/.NET Truth Release Work

- Validate private package source behavior.
- Decide whether NuGet remains scan-only or gains runtime guard support.
- Keep runtime guard claims out of stable docs until end-to-end matrix coverage exists.

### D. Policy Command Family

- Decide whether to add dedicated commands:
  - `safedeps policy init`;
  - `safedeps policy validate`;
  - `safedeps policy explain`.
- Add schema migration support only when a future policy schema version exists.

### E. UI And Dependency Operations

- Add automated browser-level UI smoke coverage, for example with Playwright or an equivalent lightweight browser runner:
  - start `safedeps ui` on a test port;
  - open the dashboard;
  - run a scan from the UI;
  - verify safe fixture passes;
  - verify bad fixture shows blocking findings;
  - verify dependency and policy panels render without server errors.
- Add a documented local UI smoke command or script so maintainers can quickly test the real browser experience before release.
- Improve install/update/uninstall workflows with clearer operation states:
  - validating;
  - blocked;
  - applied;
  - rolled back.
- Improve denial explanations and recovery guidance.
- Evaluate safe bulk updates only after strict pre/post checks are mature.
- Evaluate guided repair for missing runtime dependencies.
- Continue UI layout polish and overflow handling as product work, not as a `0.4.0` blocker.

### F. Release And Supply-Chain Publishing

- Validate `publish=false` release workflow dry runs.
- Verify PyPI Trusted Publishing or keep the API-token fallback documented.
- Validate npm provenance publishing before claiming it.
- Validate NuGet publish scope and artifact paths.
- Confirm GitHub build provenance attestations include every release artifact before promoting attestations from scaffolded to guaranteed.

### G. Adoption And Integrations

- Consider a first-party GitHub Action.
- Keep GitLab/Azure examples current.
- Keep README, UI docs, and ecosystem support docs synchronized each release.
- Add troubleshooting decision trees for shell/wrapper issues when real user feedback accumulates.

## Guardrails

- Do not broaden stable ecosystem claims without tests.
- Do not add large features before release hygiene remains green.
- Do not treat scaffolded release/publishing paths as guarantees.
- Prefer small, test-backed changes over broad rewrites.
