# Maintainer Release Process

## Scope

This internal maintainer document defines the minimum release process for SafeDeps public distribution. It is not end-user documentation.

## Preflight

Prepare the next version and release note:

```bash
python scripts/release/bump_version.py patch --note "Short release change summary"
```

Run locally before release:

```bash
python scripts/release/preflight.py --expected-version 0.2.0
```

For publish execution on a release tag, enforce tag/version consistency:

```bash
GITHUB_REF_NAME=v0.2.0 python scripts/release/preflight.py --expected-version 0.2.0 --require-tag
```

## CI Requirements

Release should happen only after:

- `safedeps` workflow passes
- tests pass
- scan artifacts are generated and validated
- release workflow `publish=true` is explicitly selected for registry publication

## Python (PyPI)

Build:

```bash
python -m pip install --upgrade pip build
python -m build
```

Publish (current `0.4.0` Beta Preview stabilization path: API token fallback only). Do not claim PyPI Trusted Publishing/OIDC until the release workflow has been validated from a non-publishing dry run and the PyPI trusted publisher configuration is confirmed.

## npm Wrapper

Pack:

```bash
cd packages/npm-wrapper
npm pack
```

Publish with provenance only after the npm package configuration and release workflow have been validated. Do not claim npm Trusted Publishing until the package is configured for it and a dry run has verified the artifact path.

## .NET Tool (NuGet)

Build package:

```bash
dotnet pack packages/dotnet-tool/SafeDeps.Tool.csproj -c Release -o artifacts/dotnet
```

Publish:

```bash
dotnet nuget push artifacts/dotnet/*.nupkg --source https://api.nuget.org/v3/index.json --api-key YOUR_KEY
```

## Release Workflow Controls

Workflow: `.github/workflows/release-template.yml`

Status for `0.4.0`: release workflow scaffold exists, but publishing and attestation paths must be validated before they are treated as production release guarantees.

- `publish=false`:
  - build + artifact validation only
  - release checksum manifest generation
  - no registry publication
- `publish=true`:
  - PyPI publish via `PYPI_API_TOKEN` when configured
  - PyPI upload runs with verbose logging and `--skip-existing` so reruns can skip already uploaded files
  - npm publish with provenance
  - NuGet publish when `NUGET_API_KEY` secret is configured
- `push tag vX.Y.Z`:
  - strict preflight tag/version check
  - publish stages enabled
  - build provenance attestation
  - GitHub Release created with artifacts + checksum manifest

## Trusted Publishing / Attestation Gate

Do not promote Trusted Publishing or release attestations from "scaffolded" to "guaranteed" until all of these are true:

- `workflow_dispatch` with `publish=false` succeeds and produces Python, npm, NuGet, and checksum manifest artifacts.
- `scripts/release/preflight.py --expected-version X.Y.Z --require-tag` passes on the release tag.
- PyPI trusted publisher configuration is verified, or the release intentionally uses the documented API token fallback.
- npm provenance publishing is verified against the expected package name and tarball path.
- NuGet publish is verified with the expected package ID and API key scope.
- GitHub build provenance attestation succeeds on a tag run and the attestation subject list includes every release artifact.

Until then, release notes should say "release workflow scaffold" or "attestation scaffold", not "Trusted Publishing enabled".

## Artifact Integrity Manifest

The release workflow generates:

- `release-artifacts/release-manifest.json`

It includes deterministic artifact listing with SHA256 digests for:

- Python `dist/*`
- npm tarball `packages/npm-wrapper/*.tgz`
- NuGet package `artifacts/dotnet/*.nupkg`

## Version Discipline

The following versions must match before release:

- `pyproject.toml` project version
- `safedeps/__init__.py` `__version__`
- `packages/npm-wrapper/package.json` version
- `packages/dotnet-tool/SafeDeps.Tool.csproj` `PackageVersion`

## Release Notes

Update release notes for every meaningful change before publishing.

Use `scripts/release/bump_version.py` for the first release-note scaffold, then replace TODO items with the concrete fixes, verification commands, and follow-up work.

Keep the active release note in the repository root while it is being prepared. Move already-published historical notes into `release-notes/old/` so the root stays focused on the current release.
