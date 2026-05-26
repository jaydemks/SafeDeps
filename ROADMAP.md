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

## Track C - Security Features (Candidate)

### C1. Stronger Trust Signals

- Add optional package-age policy defaults by manager.
- Add optional maintainer/publisher risk heuristics with explainable output.
- Improve suspicious package pattern detection and confidence scoring.

### C2. Policy And Exception Governance

- Add stronger exception lifecycle controls:
  - mandatory reason format
  - expiry reminders
  - audit trail metadata
- Add optional policy presets (`strict`, `balanced`, `learning`).

### C3. Supply-Chain Verification (Research)

- Evaluate signature/provenance verification options where ecosystem supports it.
- Evaluate checksum enforcement workflow for approved dependency sources.

## Track D - Documentation And Adoption

### D1. User Docs

- Keep README and UI docs synchronized with actual behavior each release.
- Add "UI action -> equivalent CLI command" mapping table.
- Add troubleshooting decision tree for common shell/wrapper issues.

### D2. Release Quality Gates

- Define minimum validation checklist required before PyPI/npm/NuGet publish.
- Enforce release checklist in CI for version alignment + smoke tests.

## Near-Term Milestones

### Milestone 1 (Next)

- Complete npm and NuGet deep validation.
- Stabilize any remaining wrapper edge cases.
- Publish updated docs for tested vs pending-tested flows.

### Milestone 2

- Improve guided dependency actions UX and denial explanations.
- Add regression tests for all critical runtime guard scenarios.

### Milestone 3

- Introduce selected candidate security features from Track C after feasibility review.

## Notes

- Items marked as candidate/research require feasibility validation before commitment.
- Security and runtime correctness always take precedence over new feature speed.
