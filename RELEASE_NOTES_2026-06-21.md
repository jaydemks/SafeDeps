# SafeDeps 0.5.0 Beta Preview - Release Notes (2026-06-21)

## Scope

Beta Preview release focused on turning the post-`0.4.0` hardening work into a scoped public release: required gates are stricter, Python/pip runtime guard coverage is broader, Poetry lockfile scanning is validated across a version matrix, and public claims are aligned with tested behavior.

SafeDeps `0.5.0` still does not claim broad stable runtime protection for every ecosystem. Python/pip remains the primary runtime guard path; Poetry support is stable for lockfile scanning; npm and NuGet runtime protection remain experimental until their own e2e matrices are promoted.

## Changed

- Promote the post-0.4 hardening work into a scoped 0.5.0 Beta Preview release.
- Keep stable claims focused on tested Python/pip and Poetry lockfile policy-gate paths.
- Keep npm and NuGet runtime protection and public registry publishing outside stable claims until their own gates are proven.
- Promoted the pip guard e2e workflow to blocking coverage across Bash on Ubuntu/macOS, PowerShell on Windows, CMD on Windows, Python `3.10` through `3.13`, and representative pip versions.
- Added required Poetry lockfile validation across Poetry `1.7.1`, `1.8.5`, `2.0.1`, `2.1.4`, `2.2.1`, `2.3.4`, and `2.4.1`.
- Tightened Ruff and mypy gates beyond the original beta baseline.
- Added release workflow contract coverage for publish gates, dry-run behavior, artifact manifest paths, checksums, and build-provenance artifact classes.
- Added public claim tests to keep docs aligned with the tested support scope and avoid overpromising registry publishing or runtime support.
- Updated release readiness documentation around the private top-frontier baseline, support matrix, and claim ladder.

## Verification

- `.venv/bin/python scripts/check_versions.py`
- `.venv/bin/python scripts/release/preflight.py --expected-version 0.5.0`
- `GITHUB_REF_NAME=v0.5.0 .venv/bin/python scripts/release/preflight.py --expected-version 0.5.0 --require-tag`
- `.venv/bin/python -m pytest tests/unit/test_docs_claims.py -q`
- `make checks PYTHON=.venv/bin/python` passed with `347` tests, `91.89%` coverage, package build, `twine check`, and CLI smoke.
- GitHub Actions required workflows passed on the final pre-tag validation push.
- `SafeDeps Release Template` dry-run with `publish=false` passed on `main`, producing Python, npm, NuGet, and release manifest artifacts without registry publication or GitHub Release creation.
- PyPI `0.5.0` is published and visible as the latest SafeDeps version.
- GitHub Release `v0.5.0` is published as a prerelease with Python, npm wrapper, NuGet tool, and release manifest assets.

## Still Deliberately Limited

- Keep PyPI Trusted Publishing, npm public registry publishing, NuGet public registry publishing, and npm/NuGet runtime protection outside stable claims until their own release/e2e gates prove them.
