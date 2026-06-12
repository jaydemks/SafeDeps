# SafeDeps Roadmap (Next)

This roadmap tracks the next practical milestones after the recent runtime-guard and UI stabilization work.

## Guiding Priorities

1. Security-first behavior stays the default.
2. UX must remain understandable for non-expert users.
3. Cross-platform reliability (Windows, Linux, macOS) is mandatory.

## Track A - Validation And Hardening

### A1. Deep Test Coverage For Not-Yet-Validated Flows

- Expand end-to-end validation for npm runtime guard.
- Expand end-to-end validation for NuGet/.NET runtime flows.
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

- Complete npm and NuGet deep validation.
- Stabilize any remaining wrapper edge cases.
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
