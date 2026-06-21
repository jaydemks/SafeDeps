# SafeDeps 0.5.1 Beta Preview - Release Notes (2026-06-21)

## Scope

Patch release focused on release-trust hardening. SafeDeps `0.5.1` keeps the same product support scope as `0.5.0`: Python/pip remains the primary runtime guard path, Poetry support is validated for lockfile scanning, and npm/NuGet runtime protection remains experimental.

## Changed

- Publish PyPI releases through PyPI Trusted Publishing/OIDC instead of the API-token/Twine fallback.
- Add a dedicated `pypi` release environment to the PyPI publish job.
- Keep PyPI publishing separated from build jobs so only the publish job receives `id-token: write`.
- Update release workflow contract tests so token-based PyPI publishing cannot silently return.
- Keep npm and NuGet publish paths unchanged and scoped as experimental/public-registry-limited until their own registry and provenance gates are proven.

## Verification

- `.venv/bin/python scripts/check_versions.py`
- `.venv/bin/python scripts/release/preflight.py --expected-version 0.5.1`
- `GITHUB_REF_NAME=v0.5.1 .venv/bin/python scripts/release/preflight.py --expected-version 0.5.1 --require-tag`
- `.venv/bin/python -m pytest tests/unit/test_release_workflow_contract.py -q`
- `make checks PYTHON=.venv/bin/python`

## Still Deliberately Limited

- npm public registry publishing, NuGet public registry publishing, npm runtime protection, and NuGet runtime protection remain outside stable claims until their own release/e2e gates prove them.
- This release proves the PyPI Trusted Publishing path only after the `v0.5.1` tag workflow publishes successfully.
