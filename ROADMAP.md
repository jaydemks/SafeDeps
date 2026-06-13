# SafeDeps Roadmap (Next)

This roadmap tracks the next practical milestones after the recent runtime-guard and UI stabilization work.

## Guiding Priorities

1. Security-first behavior stays the default.
2. UX must remain understandable for non-expert users.
3. Cross-platform reliability (Windows, Linux, macOS) is mandatory.

## Track A - Validation And Hardening

### A1. Deep Test Coverage For Not-Yet-Validated Flows

- Expand end-to-end validation for npm dependency protection.
- Expand end-to-end validation for NuGet/.NET dependency protection.
- Move npm and NuGet protection toward native ecosystem integration instead of relying only on generated wrappers.
- Add cross-shell validation matrix:
  - PowerShell
  - CMD
  - Bash
- Add regression suite for:
  - toggle behavior (`Auto ON/OFF`, `Project/Global`)
  - no-full-reload UI behavior
  - wrapper regeneration and activation paths

### A2. Security Regression Guardrails

- Add integration tests to ensure unpinned installs are blocked where expected.
- Add tests for "Project" vs "Global" scope boundaries.
- Add tests for self-update/source restrictions and known bypass paths.

## Track B - Install/Uninstall UX Simplification

### B1. Guided Dependency Operations (UI)

- Improve install/update/uninstall workflows with clearer pre-check status.
- Add explicit operation states per row:
  - validating
  - blocked
  - applied
- Add clearer user-facing reason messages when an operation is denied.

### B2. Safer Bulk Operations (Candidate)

- Evaluate bulk safe update flow (batch mode) with strict pre/post checks.
- Evaluate staged uninstall workflow with impact preview before confirmation.

### B3. Dependency Repair And Safe Restore (Candidate)

- Add a guided repair flow for missing runtime dependencies required by already installed packages.
- Detect cases like `pytest` requiring `colorama` and offer a safe restore instead of leaving the environment broken.
- Show dependency impact before repair/uninstall:
  - package to remove or restore
  - packages that require it
  - exact runtime scope affected (`project` or `global`)
- Add strict loop protection:
  - maximum dependency expansion depth
  - maximum number of packages per repair operation
  - explicit user confirmation before applying transitive repairs
- Keep repair operations guarded by pre/post compatibility checks (`pip check`, equivalent npm/.NET checks where available).

## Track C - UI Redesign And Visual System

### C0. Codebase Decomposition For UI Work

- Status: substantially completed in `0.3.3`.
- Split the former monolithic `safedeps/cli.py` entrypoint into focused modules for constants, scan pipeline, reports/exporters, runtime/install scope detection, dependency actions, UI state, UI rendering, UI server transport, doctor checks, and baseline/approval exceptions.
- Split guard support code into focused modules for interpreter hook installation, guard state/Auto Guard shell integration, and repository-source detection while keeping `safedeps.guard` as the setup facade.
- Split dependency/finding table rendering and runtime dependency collection out of the main UI page renderer.
- Keep `safedeps.cli` as a thin command dispatcher and compatibility facade for existing tests/imports.
- Remaining refinement: move the large bash/PowerShell/CMD wrapper templates out of `guard.py`, and continue breaking down `ui_render.py` into smaller view/template helpers as the visual redesign progresses.

### C1. Full UI Restyle

- Redesign the local web UI as a full product surface, not only incremental guard-flow fixes.
- Define a consistent layout system for:
  - header/status area
  - guard controls
  - project/system dependency tables
  - dependency action states
  - scan findings and policy forms
- Replace ad hoc spacing and table sizing with responsive rules that prevent long text, package names, paths, and error messages from overflowing their containers.
- Add visual QA checks for common desktop widths and smaller browser windows.

### C2. Interaction Polish

- Improve collapsible sections for large dependency inventories and future multi-project views.
- Add clearer empty/loading/error states for project runtime dependencies and system runtime dependencies.
- Keep guard setup/test actions visible without making advanced policy controls dominate the screen.

## Track D - Security Features (Candidate)

### D1. Stronger Trust Signals

- Add optional package-age policy defaults by manager.
- Add optional maintainer/publisher risk heuristics with explainable output.
- Improve suspicious package pattern detection and confidence scoring.

### D2. Policy And Exception Governance

- Add stronger exception lifecycle controls:
  - mandatory reason format
  - expiry reminders
  - audit trail metadata
- Add optional policy presets (`strict`, `balanced`, `learning`).

### D3. Supply-Chain Verification (Research)

- Evaluate signature/provenance verification options where ecosystem supports it.
- Evaluate checksum enforcement workflow for approved dependency sources.

## Track E - Documentation And Adoption

### E1. User Docs

- Keep README and UI docs synchronized with actual behavior each release.
- Add "UI action -> equivalent CLI command" mapping table.
- Add troubleshooting decision tree for common shell/wrapper issues.

### E2. Release Quality Gates

- Define minimum validation checklist required before PyPI/npm/NuGet publish.
- Enforce release checklist in CI for version alignment + smoke tests.

## Near-Term Milestones

### Milestone 1 (Next)

- Start npm and NuGet native protection work, using the Python-side guard as the reference quality bar.
- Complete npm and NuGet deep validation around the current wrapper-based behavior before replacing or reducing it.
- Stabilize any remaining wrapper edge cases that still affect 0.3.3 users.
- Publish updated docs for tested vs pending-tested flows.

### Milestone 2

- Improve guided dependency actions UX and denial explanations.
- Start full UI restyle work, prioritizing layout consistency and overflow fixes.
- Add regression tests for all critical runtime guard scenarios.

### Milestone 3

- Introduce selected candidate security features from Track D after feasibility review.

## Notes

- Items marked as candidate/research require feasibility validation before commitment.
- Security and runtime correctness always take precedence over new feature speed.
