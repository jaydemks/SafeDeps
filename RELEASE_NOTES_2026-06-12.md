# SafeDeps 0.3.0 - Release Notes (2026-06-12)

Urgent hardening release focused on closing direct Python interpreter bypasses.

## Fixes

- Python interpreter guard:
  - `safedeps setup` now installs a Python startup hook in the protected interpreter `site-packages`.
  - The hook intercepts guarded pip operations even when callers bypass shell wrappers and run an absolute interpreter path, for example `C:\...\python.exe -m pip install six`.
  - The hook applies the same `Project` / `Global` scope rules recorded in `.safedeps/guard-state.json`.
  - The hook blocks guarded `pip uninstall` while SafeDeps is active, except for SafeDeps self-uninstall cleanup.
  - The hook blocks unpinned runtime installs and SafeDeps self-updates from non-official sources.
- Cleanup:
  - `safedeps guard-cleanup` now removes the interpreter startup hook together with shell/profile/PATH guard state.

## Security Notes

- This closes the bypass where an automation tool, WSL shell, Codex task, or other process calls the real Python executable directly and skips PowerShell/CMD/Bash wrappers.
- The interpreter hook is loaded by normal Python startup. A process with enough privilege to run Python with `-S`, remove files from `site-packages`, or modify the protected interpreter can still bypass user-space controls. That is outside the shell-wrapper threat model and should be treated as a privileged tampering case.

## Version Updates

- `safedeps.__version__`: `0.3.0`
- `pyproject.toml`: `0.3.0`
- npm wrapper package: `0.3.0`
- .NET tool package: `0.3.0`

## Verification

- `python3 -m py_compile safedeps/guard.py safedeps/cli.py safedeps/runtime_guard.py tests/test_cli.py`
- Direct runtime guard simulation for `python -m pip install six` style invocation.
- Interpreter hook `.pth` generation check.
