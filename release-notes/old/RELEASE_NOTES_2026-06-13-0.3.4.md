# SafeDeps 0.3.4 - Release Notes (2026-06-13)

## Scope

Patch release for the packaged web UI assets.

## Fixed

- Packaged the SafeDeps UI logo inside the Python wheel so `pip install safedeps` installations can render the sidebar logo.
- Updated the UI asset route to serve the logo from installed package resources instead of the repository-only `docs/images` folder.

## Version Alignment

- `safedeps.__version__`: `0.3.4`
- `pyproject.toml`: `0.3.4`
- npm wrapper package: `0.3.4`
- .NET tool package: `0.3.4`

## Verification

- `python3 -m py_compile safedeps/*.py safedeps/assets/*.py tests/test_cli.py scripts/release/preflight.py`
- `python3 scripts/release/preflight.py --expected-version 0.3.4`
- Package-resource smoke check for `safedeps.assets/safedeps_logo.png`
- `git diff --check`

## Follow-up Queue

- Continue post-0.3.4 work on native npm and NuGet guard behavior.
