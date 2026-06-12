# SafeDeps 0.3.2 - Release Notes (2026-06-12)

Patch release focused on safer UI startup behavior.

## Fixes

- `safedeps ui` without a path now always uses the dedicated SafeDeps workspace at `~/.safedeps/workspace`.
- SafeDeps no longer treats a random current working directory as the project root just because it looks like a project.
- This avoids creating `.safedeps`, scan artifacts, or setup files in directories where the user did not explicitly choose to work.
- Project UI startup is now explicit:
  - `safedeps ui .`
  - `safedeps ui C:\path\to\project`

## Version Updates

- `safedeps.__version__`: `0.3.2`
- `pyproject.toml`: `0.3.2`
- npm wrapper package: `0.3.2`
- .NET tool package: `0.3.2`

## Verification

- `python3 -m py_compile safedeps/guard.py safedeps/cli.py safedeps/runtime_guard.py tests/test_cli.py`
- `python3 scripts/check_versions.py`
- UI path resolution tests for:
  - `safedeps ui` -> `~/.safedeps/workspace`
  - `safedeps ui .` -> current project/root
