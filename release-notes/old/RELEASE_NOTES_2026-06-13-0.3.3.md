# SafeDeps 0.3.3 - Release Notes (2026-06-13)

## Scope

UI-focused update for the local SafeDeps dashboard.

## Changed

- Reworked the local web UI into a single-page dashboard with sidebar navigation.
- Moved UI styling into `safedeps/ui_assets.py` so presentation code is separated from CLI/server behavior.
- Refactored the former monolithic `safedeps/cli.py` into focused modules:
  - `safedeps/constants.py`
  - `safedeps/scan.py`
  - `safedeps/reports.py`
  - `safedeps/runtime.py`
  - `safedeps/dependency_actions.py`
  - `safedeps/ui_state.py`
  - `safedeps/ui_render.py`
  - `safedeps/ui_server.py`
  - `safedeps/doctor.py`
  - `safedeps/exceptions.py`
- Kept `safedeps/cli.py` as the command dispatcher and backward-compatible import facade.
- Split guard support code into:
  - `safedeps/guard_hooks.py`
  - `safedeps/guard_state.py`
  - `safedeps/guard_repo.py`
- Split dependency/finding table rendering and runtime dependency collection into `safedeps/ui_dependencies.py`.
- Added responsive dark/light glass-style layout, page navigation, table/form overflow handling, and guided tooltips.
- Added local logo serving through `/assets/safedeps-logo.png`.
- Clarified README project-vs-global guard test commands so local `.venv` development installs and PyPI/system installs use explicit Python executables.
- Moved historical release notes into `release-notes/old/`, leaving the active `0.3.3` release note in the repository root.
- Updated release preflight so it validates the active root release note for the current version instead of requiring a historical note file.
- Moved release-process documentation under `docs/maintainers/` and removed maintainer-only release commands from the user-facing README.
- Removed local machine paths from README examples and aligned the .NET package repository URL metadata.
- Removed the stale generated `release-artifacts/release-manifest.json` file from source control and ignored future release artifact outputs.
- Removed obsolete `ROADMAP_OLD.md`; `ROADMAP.md` is now the single active roadmap and tracks npm/NuGet native-protection work as the next post-0.3.3 focus.
- Added a Live Guard State loading skeleton for `Setup Guard`, Auto Guard toggles, and Project/Global scope changes so guard operations show a clear non-clickable pending state.
- Fixed a UI JavaScript scope error in the project path sync handler that could stop later dashboard scripts from running.
- Reworked the `Run Scan` path Browse action into an in-app project-path modal, avoiding browser prompts and native file dialogs while keeping all scan forms synchronized.
- Replaced the global topbar search with per-dependency-list filters so search only applies to long scan result lists.

## Fixed

- Removed the always-running Overview scanline animation.
- Moved the SafeDeps logo into the top-left brand icon slot and kept it centered in collapsed sidebar mode.
- Removed the duplicate top sidebar collapse button; the lower sidebar control remains the only collapse action.
- Restored system/runtime dependency visibility when the UI runtime Python does not provide `python -m pip list`, using `importlib.metadata` as fallback.

## Version Updates

- `safedeps.__version__`: `0.3.3`
- `pyproject.toml`: `0.3.3`
- npm wrapper package: `0.3.3`
- .NET tool package: `0.3.3`

## Verification

- `python3 -m py_compile safedeps/*.py tests/test_cli.py`
- `python3 -c "import safedeps.cli as c; print(c.main(['version'])); print(c._resolve_ui_start_path('.'))"`
- `python3 -m safedeps.cli scan examples/safe-project --out .tmp-security --fail-on HIGH`
- `python3 -m safedeps.cli scan examples/bad-project --out .tmp-security --fail-on HIGH`
- `PYTEST_CURRENT_TEST=1 python3 -m safedeps.cli setup /tmp/safedeps-setup-smoke --force --install-scope project`
- UI render smoke test
- Local logo route smoke test
- `python3 -m pytest tests/test_cli.py` was not executed because this interpreter does not have `pytest` installed.

## Follow-up Queue

- Manual cross-browser UI pass for desktop and narrow viewports.
- Move generated wrapper templates out of `safedeps/guard.py`.
- Continue decomposing `safedeps/ui_render.py` while implementing the next UI update.
