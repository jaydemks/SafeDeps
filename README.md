# SafeDeps

SafeDeps is a dependency safety gate.

It checks your project dependencies before install/update and can block risky changes (for example vulnerable, untrusted, or floating versions).

It works with Python, npm, NuGet, and Git dependency definitions.

## Start In 60 Seconds

1. Install SafeDeps:

```bash
pip install safedeps
```

2. In your project folder, run one-time setup:

```bash
safedeps setup .
source .safedeps/activate.sh
```

3. Open the UI:

```bash
safedeps ui . --open-browser
```

Default UI URL: `http://127.0.0.1:8765`

4. Run scan from UI or CLI:

```bash
safedeps scan . --fail-on HIGH
```

After `source .safedeps/activate.sh`, `pip install ...` in that project shell is automatically guarded by SafeDeps.

## What It Is (Simple)

SafeDeps is a guardrail you run before installing or updating dependencies.

It helps you block risky dependency changes early, for example:

- unpinned/floating versions
- untrusted registries/sources
- known vulnerable packages (from configured local intelligence/feed)
- missing lockfiles
- suspicious package patterns

In short: it is a backend safety gate for dependency workflows in local dev and CI.

## Current State

- Core engine: Python CLI/library (`safedeps` package)
- npm distribution: wrapper package present in `packages/npm-wrapper`
- .NET global tool wrapper: implemented in `packages/dotnet-tool`
- Security outputs:
  - `security-artifacts/safedeps-report.json`
  - `security-artifacts/safedeps-sbom.json`

## Versioning Policy

- Single public version for all official distributions.
- Python core package version in `pyproject.toml` must match:
  - `safedeps/__init__.py` (`__version__`)
  - `packages/npm-wrapper/package.json` (`version`)
- Release tags must follow `vX.Y.Z`.
- No package publish if versions are inconsistent.
- CI enforces this with `python scripts/check_versions.py`.

## Features

- Central policy file: `.safedeps/policy.json`
- Python scanning:
  - `requirements*.txt`
- npm scanning:
  - `package.json`
  - `.npmrc`
  - lockfile presence checks
  - install lifecycle scripts checks
  - `pnpm-lock.yaml` deep parsing (PyYAML-backed)
- .NET scanning:
  - `.csproj`
  - `NuGet.Config`
  - lockfile presence checks
- Git dependency checks:
  - `.gitmodules`
- Rule enforcement:
  - denylist packages
  - floating/unpinned versions
  - untrusted registries/indexes
  - expired exceptions
- CI-friendly exit codes

## Install

### Python (local development)

```bash
pip install .
```

Install with development tooling (tests):

```bash
pip install .[dev]
```

Or bootstrap a local virtual environment automatically:

```bash
./scripts/bootstrap_dev.sh
```

### Python (from PyPI, after publish)

```bash
pip install safedeps
```

### npm (from wrapper package)

From this repository:

```bash
cd packages/npm-wrapper
npm install -g .
```

From npm registry (after publish):

```bash
npm install -g safedeps
```

### .NET

From this repository (after pack/install):

```bash
dotnet tool install --global --add-source ./artifacts/dotnet SafeDeps.Tool
```

Command:

```bash
safedeps-dotnet scan .
```

From NuGet (after publish):

```bash
dotnet tool install -g SafeDeps.Tool
```

## Quickstart

```bash
safedeps init
safedeps scan .
```

One-time project auto-configuration (guard `pip install` automatically in this project shell):

```bash
safedeps setup .
source .safedeps/activate.sh
```

Fail CI on high/critical findings:

```bash
safedeps scan . --fail-on HIGH
```

Optional online npm audit:

```bash
safedeps scan . --online-audit
```

Optional SARIF export:

```bash
safedeps scan . --sarif security-artifacts/safedeps.sarif
```

Optional CycloneDX export:

```bash
safedeps scan . --cyclonedx security-artifacts/safedeps.cdx.json
```

Optional SPDX export:

```bash
safedeps scan . --spdx security-artifacts/safedeps.spdx.json
```

Optional HTML export:

```bash
safedeps scan . --html security-artifacts/safedeps-report.html
```

Exporter notes:

- SARIF includes rule catalog and severity mapping.
- CycloneDX/SPDX exporters deduplicate repeated components.
- SPDX and CycloneDX include purl metadata when manager/version are available.

Validate local setup and metadata cache health:

```bash
safedeps doctor .
```

Explain a specific finding rule:

```bash
safedeps explain FLOATING_VERSION
```

Create vulnerability baseline from the latest report:

```bash
safedeps baseline . --report security-artifacts/safedeps-report.json --output .safedeps/vuln-baseline.json
```

Add/update an expiring suppression entry:

```bash
safedeps approve . --manager npm --rule FLOATING_VERSION --package lodash --file package.json --expires 2026-12-31
```

Run the local visual UI:

```bash
safedeps ui . --open-browser
```

The UI is fully in English and includes visual flows for:

- scan execution
- rule explanation (`explain`)
- baseline generation (`baseline`)
- expiring approvals (`approve --expires`)
- one-click finding pickup ("Use For Approval") to prefill approval fields
- pip install guard panel showing blocking pip findings and reasons
- intelligence editor for `.safedeps/vuln-feed.json` and `.safedeps/metadata-cache.json`
- one-click starter template generation for local "safe" intelligence files

UI options:

- `--host` (default `127.0.0.1`)
- `--port` (default `8765`)
- `--fail-on` (default `HIGH`)

## Minimal Policy Example

```json
{
  "allowed_registries": {
    "npm": ["https://registry.npmjs.org/"],
    "pip": ["https://pypi.org/simple", "https://pypi.org/simple/"],
    "nuget": ["https://api.nuget.org/v3/index.json"]
  },
  "deny_packages": ["malicious-demo-package"],
  "allow_unpinned": false,
  "require_lockfiles": true,
  "require_expiring_exceptions": true,
  "exceptions": [
    {
      "manager": "npm",
      "package": "demo-package",
      "rule": "FLOATING_VERSION",
      "expires": "2026-12-31",
      "reason": "Temporary migration exception"
    }
  ]
}
```

Vulnerability baseline support:

- Default file: `.safedeps/vuln-baseline.json`
- Matching findings can be suppressed via `suppress` entries (`manager`, `rule`, `package`, `file`).
- Suppression entries may include optional `expires` (`YYYY-MM-DD`); expired entries are ignored.

Local vulnerability feed support:

- Optional file: `.safedeps/vuln-feed.json`
- Supported fields per entry: `manager`, `package`, `id`, `severity`, `message`
- Optional OSV-style entries via `vulnerabilities_osv` are also supported in `.safedeps/vuln-feed.json`.
- Severity is normalized to SafeDeps scale (`CRITICAL/HIGH/MEDIUM/LOW/INFO`).
- You can create/edit/validate this file directly from the UI ("Intelligence Settings"), no manual file editing required.

Local metadata cache support:

- Optional file: `.safedeps/metadata-cache.json`
- Used by age/churn/maintainer risk signals.
- You can create/edit/validate this file directly from the UI ("Intelligence Settings").

## Verification Workflow

Run these checks before release:

1. `safedeps scan examples/bad-project` must fail (`exit code 2`).
2. `safedeps scan examples/safe-project` should pass or produce only accepted non-blocking findings.
3. `python -m pytest` must pass.
4. CI must fail on an intentionally unsafe fixture branch.

## Publishing

### Python / PyPI

```bash
python -m build
python -m twine upload dist/*
```

### npm

```bash
cd packages/npm-wrapper
npm publish --access public
```

### .NET / NuGet (planned)

```bash
dotnet pack packages/dotnet-tool/SafeDeps.Tool.csproj -c Release -o artifacts/dotnet
dotnet nuget push artifacts/dotnet/*.nupkg --source https://api.nuget.org/v3/index.json --api-key YOUR_KEY
```

Use trusted publishing/OIDC whenever available.

## Release Automation (Template)

Run local preflight checks before triggering a release:

```bash
python scripts/release/preflight.py --expected-version 0.2.1
```

Release workflow template:

- `.github/workflows/release-template.yml`
- includes:
  - preflight checks
  - Python distribution build artifact
  - npm wrapper tarball artifact
  - .NET tool `.nupkg` artifact
  - release checksum manifest (`release-artifacts/release-manifest.json`)
  - optional publish gates (`publish=true`) for PyPI/npm/NuGet
  - tag-triggered release flow on `v*` tags
  - GitHub release publication with attached artifacts
  - build provenance attestation stage

Detailed process guide:

- `docs/release/RELEASE_PROCESS.md`

Artifact validation helper:

```bash
python scripts/validate_artifacts.py security-artifacts
```

## CI Templates

Ready-to-copy templates are available in `examples/ci/` for:

- GitHub Actions
- GitLab CI
- Azure Pipelines

See `examples/ci/README.md` for usage details.

## Pre-commit Integration

This repository includes a ready pre-commit hook config:

- `.pre-commit-config.yaml`

Install and enable:

```bash
pip install pre-commit
pre-commit install
```

The hook runs:

```bash
safedeps scan . --fail-on HIGH --out security-artifacts
```

## Security Scope

SafeDeps is a preventive gate, not a guarantee that every package is safe.

It should be used with lockfiles, code review, SBOM analysis, vulnerability feeds, signed releases where supported, and CI policy enforcement.
