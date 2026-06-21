# SafeDeps Roadmap (Next)

This file tracks work after the `v0.4.0` Beta Preview stabilization roadmap.

`MAIN_ROADMAP.md` is the authoritative record for the long stabilization push that brought SafeDeps to the current pre-release state. This file should stay focused on future work only, so old completed items are not repeated as active TODOs.

## Current Baseline

Status after `MAIN_ROADMAP.md` reconciliation:

- `v0.4.0` Beta Preview stabilization work is released.
- Local gate is green: `345` tests, `91.89%` coverage, package build, `twine check`, and CLI smoke.
- Architecture checklist is complete: CLI parser, scan pipeline, package-manager adapters, verifier interface, reporter registry, guard backend install layer, policy schema validation.
- Python/pip is the primary stable runtime guard path.
- npm and NuGet scan support are validated, while runtime protection remains limited or experimental unless explicitly documented otherwise.
- Local UI smoke has been manually validated from the native Windows side for the core Python/safe/bad fixture path.
- PyPI `0.4.0` is published; npm and NuGet packages are built as release artifacts but are not published to their public registries yet.
- GitHub Release assets and build provenance exist for `v0.4.0`; PyPI Trusted Publishing, npm provenance publishing, and NuGet registry publishing remain future validation work.
- Honest claim status: SafeDeps now has strong evidence for the tested local dependency policy-gate scope and is tracked against a private top-frontier baseline. It should not claim stable release signing, Trusted Publishing, npm runtime protection, NuGet runtime protection, or public registry publishing until those areas have their own green, blocking evidence.

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

## Immediate Post-v0.4 Work

These are the first items after the `v0.4.0` tag, before adding larger product features:

Version target: use `0.4.1` for the first hardening release. Do not jump to `0.5.0` until SafeDeps has genuinely stronger guarantees: required e2e gates are green without hidden failures, static analysis is stricter, and the claim-hardening checklist below is mostly complete.

1. Make CI truthfully blocking again: remove `continue-on-error` from stable workflows only after each affected job is green locally and remotely.
2. Fix Windows e2e failures instead of masking them, especially pip guard and shell-wrapper paths.
3. Promote e2e pip from diagnostic to required once the matrix has no hidden failing cases.
4. Strengthen Ruff and mypy so quality jobs catch more than syntax-level errors.
5. Add explicit compatibility matrices for pip versions and Poetry versions before broadening support claims.
6. Keep npm and NuGet registry publishing out of stable claims until token scope, package identity, provenance, and publish dry runs are proven.

Suggested release ladder:

- `0.4.1`: CI truth hardening. Fix hidden failing jobs, reduce `continue-on-error`, keep registry claims unchanged.
- `0.4.2`: pip guard compatibility expansion. Add harder pip install cases and a broader pip-version matrix.
- `0.4.3`: static analysis hardening. Tighten Ruff and mypy in small, passing steps.
- `0.4.4`: Poetry and release-trust validation. Add Poetry matrix work and verify publishing/attestation claims.
- `0.4.5`: claim evidence and release-candidate readiness. Align public claims with the tested support scope and top-frontier baseline.
- `0.5.0`: claim upgrade only if required gates are truly blocking and the supported-scope evidence is documented.

Do not advance package versions at the start of a local hardening cycle. Change version files only when the next release scope is verified and the final release candidate is ready.

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

### 0.4.2 Next: pip Guard Compatibility Expansion

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

### 0.4.5 In Progress: Claim Evidence And Release Candidate Readiness

Status: local documentation and claim-contract work in progress. Keep package version files at `0.4.0` until the final release candidate is intentionally cut.

- [x] Document supported-scope evidence for the tested SafeDeps policy-gate paths without naming private benchmark targets in public docs.
- [x] Keep comparison claims aligned with the tested support scope and private top-frontier baseline.
- [x] Update ecosystem support to include Poetry lockfile scan validation without promoting Poetry runtime interception.
- [x] Add documentation claim tests so future wording cannot silently overpromise Trusted Publishing, npm runtime protection, NuGet runtime protection, or public registry publishing.
- [x] Verify local gates after this evidence-pack update: `345` tests, `91.89%` coverage, package build, `twine check`, and CLI smoke.
- [ ] Verify GitHub Actions after push.
- [ ] Decide whether the next release should be `0.5.0` only after all required gates remain green and release notes match the scoped claim.

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
