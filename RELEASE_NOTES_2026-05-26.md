# SafeDeps 0.2.5 - Update Notes (2026-05-26)

## Summary

Post-release stabilization update focused on Windows guard reliability and UI behavior consistency.

## Fixes Included

- Guard wrappers stability on Windows PowerShell:
  - fixed wrapper activation pathing issues
  - moved PowerShell session guard binding to `.ps1` wrappers for consistency
  - fixed PowerShell path token parsing edge case that caused runtime regex errors
- Runtime guard command path robustness:
  - scan checks in wrappers now use `python -m safedeps.cli scan ...` against the active interpreter context
- UI interaction fixes:
  - guard toggles (`Auto ON/OFF`, `Project/Global`) now submit correctly on first click in AJAX mode
  - no full-page refresh for guard actions
  - dependency list remains visible after toggle/setup actions
- UX/clarity improvements:
  - guard messages moved near dependency list
  - advanced findings moved into a collapsible panel
  - field/button tips improved for better discoverability
- advanced-only UI sections are now collapsible by default and labeled `(Advanced)` to reduce confusion for non-expert users
- Safe Update hardening (pip/npm):
  - snapshot current package version before update/install/uninstall
  - run post-change compatibility checks (`pip check` for pip, `npm ls --depth=0` for npm)
  - automatic rollback of the changed package if compatibility checks fail
  - explicit error when rollback fails, so breakage is visible immediately
- Dependency UX refinements:
  - quick-action buttons now stay aligned even when labels are longer
  - Safe Update can request approval directly in an overlay (confirm/cancel), without redirecting users to another section
  - dependency list remains visible after dependency action errors and now shows clearer user-facing error messages

## Documentation Alignment

- README updated with explicit test status:
  - Python + pip flow validated
  - npm and NuGet runtime end-to-end validation still in progress
- UI documentation aligned with current startup command and behavior.
