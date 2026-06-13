# SafeDeps 0.2.5 - Release Notes (2026-05-25)

## Summary

This release focuses on runtime guard hardening and a significantly more user-friendly UI workflow.

## Highlights

- Runtime guard hardening for Python package operations:
  - Guard now blocks unpinned runtime installs (for example `pip install colorama`) and requires exact versions.
  - Guard coverage includes both `pip ...` and `python -m pip ...` paths via generated wrappers.
- Official-source enforcement for SafeDeps self-update:
  - SafeDeps self-install/update is restricted to the repository official Git origin configured for the project.
- UI workflow improvements:
  - `Run Scan` renamed to `Re-Scan`.
  - Initial scan is executed automatically when opening the UI.
  - Dependency table now includes runtime-installed packages, not only findings/manifests.
  - Per-row quick actions support direct `Approve`, `Uninstall`, and `Safe Update` flows.
  - Dynamic partial UI updates for actions and re-scan (reduced full-page reload behavior).
- Guard setup improvements:
  - Auto-setup path on UI startup when project setup is missing.
  - New CLI quick help command: `safedeps help`.
  - New protection scope toggle:
    - `Project Only` (default for venv installs)
    - `Global` (default for system-wide installs)
    - configurable from UI guard controls.
- Scanner robustness:
  - Safer recursive traversal for Windows and transient folders (`.venv*`, caches, `node_modules`, etc.).
  - Policy support for path exclusions (`exclude_paths`) to reduce fixture/sample noise in real project scans.

## Versioning

- Python package version: `0.2.5`
- npm wrapper version: `0.2.5`
- `safedeps.__version__`: `0.2.5`

## Upgrade Notes

1. Reinstall/update local editable environment:

```bash
python -m pip install -e .[dev]
```

2. Regenerate project wrappers:

```bash
python -m safedeps.cli setup .
```

3. Re-activate guard in current shell session after setup.

## Known Notes

- Runtime guard behavior is intentionally strict for unpinned installs.
- For maintenance workflows, use controlled activation/deactivation strategy per shell session.
