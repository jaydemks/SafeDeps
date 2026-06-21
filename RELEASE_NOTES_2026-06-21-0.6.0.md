# SafeDeps 0.6.0 Beta Preview - Release Notes (2026-06-21)

## Scope

SafeDeps `0.6.0` is a stronger Beta Preview focused on production-grade evidence for the tested policy-gate scope. It promotes the post-`0.5.1` hardening work into a release candidate-style baseline: PyPI release trust is proven through Trusted Publishing, GitHub Actions are SHA-pinned, package intelligence is broader, npm has a first blocking runtime slice, and NuGet has strong scan/CI validation.

SafeDeps still does not claim stable runtime protection for every ecosystem. Python/pip remains the primary stable runtime guard path. npm runtime protection is limited to the first validated blocking slice. NuGet is supported as a scan/CI policy gate, but NuGet runtime interception is not claimed because SafeDeps does not yet install a dedicated `dotnet` command interceptor.

## Changed

- Proved PyPI Trusted Publishing/OIDC through the `0.5.1` patch release path.
- Kept GitHub Actions pinned to full commit SHAs with contract tests preventing mutable action refs.
- Expanded deterministic package intelligence with OSV-style local advisory ingestion, metadata-risk signals, and policy controls.
- Raised targeted security-critical modules to deliberate `100%` line and branch coverage.
- Promoted npm runtime validation to a first blocking slice for Node/npm from Actions `setup-node` 22 on Ubuntu Bash and Windows PowerShell/CMD.
- Added npm runtime e2e coverage for install, uninstall, update, package-lock, and lifecycle-script cases.
- Added npm scan coverage for workspaces, aliases, git dependencies, tarball URLs, local path dependencies, and registry/source behavior.
- Expanded NuGet scan validation for `NuGet.Config`, source mapping, private feeds, lockfile components, transitive packages, and case-insensitive config path handling.
- Added NuGet e2e coverage for exact `dotnet add package`, floating/range `dotnet add package`, untrusted package sources, and `dotnet restore --use-lock-file` on Ubuntu/Windows with .NET 8/9 SDKs.
- Reworked npm and NuGet e2e workflows into dedicated scripts to keep CI maintainable and human-readable.
- Added documentation claim tests so NuGet runtime protection cannot be silently promoted without a real `dotnet` interception design.

## Verification

- `.venv/bin/python scripts/check_versions.py`
- `.venv/bin/python scripts/release/preflight.py --expected-version 0.6.0`
- `GITHUB_REF_NAME=v0.6.0 .venv/bin/python scripts/release/preflight.py --expected-version 0.6.0 --require-tag`
- `.venv/bin/python -m pytest tests/unit/test_docs_claims.py tests/unit/test_release_workflow_contract.py -q`
- `make checks PYTHON=.venv/bin/python`
- GitHub Actions required workflows passed after the final `0.5.4` NuGet validation push.

## Still Deliberately Limited

- npm runtime protection remains limited to the tested first blocking slice until broader Node/npm/package-manager behavior is green.
- NuGet runtime protection is not claimed until SafeDeps has a dedicated `dotnet` command interception design and matching e2e evidence.
- npm and NuGet public registry publishing remain outside stable claims until their own registry trust and provenance paths are proven.
