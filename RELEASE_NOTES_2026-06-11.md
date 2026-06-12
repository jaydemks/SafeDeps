# SafeDeps 0.2.10 - Release Notes (2026-06-11)

Guard hardening release focused on making `Project` and `Global` protection semantics explicit and enforceable.

## Fixes

- Global guard behavior:
  - `Global` scope no longer depends on project path or virtualenv state.
  - Runtime install wrappers keep enforcing dependency policy anywhere the guard is active.
- Project guard behavior:
  - `Project` scope now records the protected project root in `.safedeps/guard-state.json`.
  - Selecting `Project` from the UI prepares project guard setup for the selected root when setup is missing.
  - Project protection works even when SafeDeps itself is installed system-wide, as long as the selected project root has guard setup.
- Shell wrapper reliability:
  - Bash wrappers are generated with LF line endings to avoid `/usr/bin/env: bash\r` failures on Linux/WSL.
  - `pip`, `python -m pip`, and `npm` wrappers now share consistent scope handling.
  - The npm bash wrapper now defines the Python executable used for SafeDeps scans.
  - Setup now generates `.safedeps\activate.bat` so CMD can activate SafeDeps wrappers explicitly, matching PowerShell and Bash activation flows.
  - Auto Guard on Windows now configures CMD startup through the current-user Command Processor `AutoRun` hook, so new CMD sessions get the guard path before system Python paths.
  - CMD wrappers now enforce `Global` scope instead of delegating directly to the real command.
  - CMD wrappers now use delayed variable expansion so scope/project/virtualenv decisions are evaluated at runtime inside guarded blocks.
  - CMD wrappers now run the SafeDeps import probe without wrapping the quoted Python executable in a parenthesized command group, avoiding CMD parsing failures that caused pass-through installs.
  - CMD wrappers now invoke the captured Python executable through `call "!_real_python!"`, avoiding CMD quote parsing failures for `python -c "import safedeps"`.
  - Windows setup now keeps POSIX extensionless wrappers (`pip`, `python`, `npm`) out of `.safedeps\bin` and writes them to `.safedeps\bin-posix`, so CMD resolves `pip.cmd` first instead of an ambiguous extensionless wrapper.
  - Windows setup removes stale extensionless wrappers from `.safedeps\bin` when refreshing guard setup.
  - CMD wrappers now fail closed for guarded `install`, `uninstall`, and `download` operations if the captured Python interpreter cannot import SafeDeps, instead of silently delegating to real pip.
  - CMD wrappers now read `protection_scope` from `guard-state.json` through Python JSON parsing instead of `findstr`, fixing `Global` scope detection in CMD.
  - `setup --install-scope system` now sets `Global` protection by default, and `--protection-scope project|global` can be used to make the intended protection scope explicit.
  - The UI server now ignores client disconnects while sending HTML responses instead of printing noisy socket tracebacks.
- CLI usability:
  - Added `safedeps version` and `safedeps --version` so the active installation can be verified before guard tests.
- UI project selection:
  - `safedeps ui .` now uses the current project root for `Project path`.
  - `safedeps ui` now prefers the current directory when it looks like a project, falling back to `~/.safedeps/workspace` only outside project folders.
- UI dependency inventory:
  - Project installs now show a single project dependency view instead of splitting `.venv` packages into a separate runtime section.
  - Declared project dependencies and installed runtime packages are merged by manager/package.
  - The dependency table now shows separate `Declared` and `Installed` columns, for example `pytest >=8.0` and installed `pytest 9.0.3` on the same row.
  - System-wide installs still keep project runtime and system runtime dependency sections separate.
  - Runtime dependency collection now uses bounded subprocess timeouts so slow or intercepted `pip list` / `npm ls` calls cannot freeze scan/toggle UI updates.
- Dependency actions:
  - UI uninstall now checks `pip show <package>` `Required-by` metadata before removal.
  - Packages required by other installed packages are blocked before uninstall, avoiding a remove-then-rollback cycle.
  - Dependency action failures now use `Dependency action error` instead of `Scan error`.
  - Compatibility rollback messages now distinguish uninstall failures from update failures.
- Install-mode isolation:
  - Added an internal install-mode boundary for project vs system installs.
  - Project installs now force project-only behavior from one central decision point.
  - System installs keep project/global action routing available without changing the validated project-install baseline.
  - UI and setup commands now accept an explicit `--install-scope project|system` override for clean regression testing.
  - Guard scope toggles now receive the resolved install scope, so system installs can switch to `Global` even when the surrounding shell has virtualenv state.
- Reset/reinstall tooling:
  - Added cross-platform reset scripts for clearing broken guard state and stale shell/profile hooks.
  - Added repo-local reinstall helper scripts for quickly testing system and project installs from the current checkout.
  - `safedeps setup` now clears stale guard hooks/wrappers before regenerating them, then restores Auto Guard if it was already enabled.
  - `safedeps guard-cleanup` now uses the unified guard cleanup path to disable Auto Guard state, PowerShell profile hooks, CMD `AutoRun`, and SafeDeps PATH entries.
  - Guard wrappers call `guard-cleanup` before allowing `pip uninstall safedeps` / `python -m pip uninstall safedeps`, reducing the risk of uninstalling SafeDeps while stale shell hooks remain active.
- Documentation:
  - README reinstall/reset instructions are split by platform and by target scope (`project` `.venv` vs system install).
  - README now documents how to verify the active Python interpreter and avoid confusing package CLI checks such as `colorama --version`.
  - README now includes ordered UI and dependency-action smoke tests for project and system installs, including `six` install/uninstall checks.
  - README now documents CMD activation via `.safedeps\activate.bat` and how to verify that CMD resolves SafeDeps `.cmd` wrappers first.
  - README now includes explicit safe uninstall flows for project `.venv` installs and system installs across PowerShell, CMD, and Bash.
  - Reset tooling now removes SafeDeps CMD `AutoRun` hooks as well as PowerShell profile hooks and PATH entries.

## Roadmap Follow-up

- Added a candidate roadmap item for dependency repair and safe restore flows.
- Future repair work should detect missing dependencies required by installed packages, offer a guarded restore, and limit transitive repair depth to avoid unbounded dependency chains.
- Added a dedicated roadmap track for a full UI restyle, separate from the guard-flow fixes in this release.

## Known Issues

- The current local web UI still has visual layout debt. Some long labels, paths, package names, table content, or error messages can overflow their containers at certain browser widths.
- The next UI milestone should address this with a full responsive layout pass rather than isolated CSS fixes only.

## Version Updates

- `safedeps.__version__`: `0.2.10`
- `pyproject.toml`: `0.2.10`
- npm wrapper package: `0.2.10`
- .NET tool package: `0.2.10`

## Verification

- `python3 -m py_compile safedeps/guard.py safedeps/cli.py`
- `python3 -m py_compile safedeps/cli.py tests/test_cli.py`
- targeted cleanup tests for preserving Auto Guard during setup cleanup and disabling it during uninstall cleanup
- `python3 -m safedeps.cli setup .`
- Project-scope runtime guard checks for:
  - `pip install <unpinned-package>`
  - `python -m pip install <unpinned-package>`
- Manual render checks for:
  - project install dependency table merging `Declared` and `Installed` rows
  - dependency action errors no longer using the scan-error label
  - uninstall pre-block for packages required by other installed packages
- `python3 -m safedeps.cli doctor .`

## Release Notes

Publishing to GitHub does not automatically update already installed PyPI/npm/NuGet packages. Users must upgrade from the selected channel after a package release is published, for example:

```bash
python -m pip install --upgrade safedeps
```

Installing directly from Git uses the current repository state for that install command, but an existing installed package still needs an explicit upgrade/reinstall command.

For local development, use editable install from the repository root:

```bash
python -m pip install -e ".[dev]"
```

`pip install safedeps` installs the latest published PyPI package, which can be older than the local checkout.
