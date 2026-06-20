# SafeDeps 0.4.0 Beta Preview Pre-Release Review

This checklist is for the final human review before committing, tagging, or publishing `v0.4.0`.

Do not create the tag or publish artifacts until this review is complete.

## 1. Confirm Scope

SafeDeps `0.4.0` is a Beta Preview stabilization release.

It should claim:

- Python/pip is the primary stable runtime guard path.
- npm and NuGet scan support is validated, but runtime protection remains limited or experimental.
- Release workflow, Trusted Publishing, and attestations are scaffolded or gated until validated.

It should not claim:

- all malicious packages are blocked;
- npm/NuGet runtime guards are fully stable;
- PyPI Trusted Publishing is already guaranteed;
- release attestations are guaranteed before a successful tag workflow run.

## 2. Local Gate

Run:

```bash
make checks PYTHON=.venv/bin/python
```

Expected:

- Ruff passes.
- mypy passes.
- pytest coverage passes above the configured gate.
- package build succeeds.
- `twine check dist/*` passes.
- CLI smoke commands pass.

Clean generated artifacts after review if not publishing from the local build:

```bash
rm -rf coverage.xml dist build safedeps.egg-info safedeps-0.4.0
```

## 3. Version And Release Preflight

Run:

```bash
.venv/bin/python scripts/check_versions.py
.venv/bin/python scripts/release/preflight.py --expected-version 0.4.0
```

Expected:

- all package versions are `0.4.0`;
- release preflight passes;
- active release notes mention `0.4.0`.

The tag-gated check should only be run after creating or simulating the release tag context:

```bash
GITHUB_REF_NAME=v0.4.0 .venv/bin/python scripts/release/preflight.py --expected-version 0.4.0 --require-tag
```

## 4. Manual Product Smoke

Run safe fixture:

```bash
.venv/bin/python -m safedeps.cli scan examples/safe-project --fail-on HIGH --out /tmp/safedeps-safe-review
```

Expected:

- command exits `0`;
- report is generated.

Run bad fixture:

```bash
.venv/bin/python -m safedeps.cli scan examples/bad-project --fail-on HIGH --out /tmp/safedeps-bad-review
```

Expected:

- command exits non-zero;
- findings are understandable and actionable.

## 5. Docs Review

Review:

- `README.md`
- `docs/KNOWN_LIMITATIONS.md`
- `docs/THREAT_MODEL.md`
- `docs/ECOSYSTEM_SUPPORT.md`
- `docs/COMPARISON.md`
- `docs/maintainers/RELEASE_PROCESS.md`
- `RELEASE_NOTES_2026-06-18.md`

Check that stable, limited, experimental, and release-gated language is consistent.

## 6. Deferred Work That Must Not Block 0.4.0

These are intentionally not release blockers for `0.4.0`:

- advanced pip edge cases such as constraint-file combinations, direct wheel URLs, and local path installs;
- npm workspace, alias, git dependency, tarball URL, and local path coverage;
- private NuGet source validation;
- future policy migration and dedicated `safedeps policy ...` command family;
- Trusted Publishing and release attestations, until validated in the release workflow.

Track these as follow-up work for post-`0.4.0` hardening.

## 7. Final Git/Release Step

Only after review:

1. inspect `git status`;
2. review the full diff;
3. commit intentionally;
4. run the preflight again;
5. create `v0.4.0`;
6. validate the tag workflow before claiming publishing or attestation guarantees.
