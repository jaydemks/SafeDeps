# SafeDeps 0.3.1 - Release Notes (2026-06-12)

Patch release for the interpreter-level guard introduced in `0.3.0`.

## Fixes

- The Python interpreter guard now respects `Auto OFF`.
- When `.safedeps/guard-state.json` has `auto_guard=false`, direct interpreter calls such as `python -m pip install six` are no longer blocked by the `.pth` startup hook.
- Manual shell activation remains separate: if a user explicitly activates `.safedeps/activate.ps1`, `.safedeps/activate.bat`, or `.safedeps/activate.sh`, the shell wrappers still protect that session.

## Version Updates

- `safedeps.__version__`: `0.3.1`
- `pyproject.toml`: `0.3.1`
- npm wrapper package: `0.3.1`
- .NET tool package: `0.3.1`

## Verification

- `python3 -m py_compile safedeps/guard.py safedeps/cli.py safedeps/runtime_guard.py tests/test_cli.py`
- `python3 scripts/check_versions.py`
- Runtime guard simulation for:
  - Auto ON blocks direct `python -m pip install six`
  - Auto OFF allows the interpreter hook to pass through
