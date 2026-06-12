# Release Process (Template)

## Scope

This document defines the minimum release process for SafeDeps public distribution.

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

Publish (recommended: Trusted Publishing/OIDC).

## npm Wrapper

Pack:

```bash
cd packages/npm-wrapper
npm pack
```

Publish (recommended: npm Trusted Publishing).

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

- `publish=false`:
  - build + artifact validation only
  - release checksum manifest generation
  - no registry publication
- `publish=true`:
  - PyPI publish via OIDC trusted publishing
  - npm publish with provenance
  - NuGet publish when `NUGET_API_KEY` secret is configured
- `push tag vX.Y.Z`:
  - strict preflight tag/version check
  - publish stages enabled
  - build provenance attestation
  - GitHub Release created with artifacts + checksum manifest

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
