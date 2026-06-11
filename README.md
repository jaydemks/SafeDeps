# SafeDeps

![SafeDeps Banner](docs/images/safedeps_banner_2026.png)

SafeDeps is a local dependency firewall.

It checks dependency changes before they are installed, committed, or accepted in CI. The goal is simple: make risky dependency changes harder to introduce by accident.

This is useful when developers, scripts, or AI coding agents can add packages to a project.

SafeDeps does not try to prove that every package is safe. It enforces your dependency policy before the change goes through.

## Quick example

With the guard active, this is blocked:

```bash
pip install requests
```

```text
Blocked: unpinned runtime install is not allowed.
Use exact versions (example: package==1.2.3).
```

This can pass, if the project policy allows it:

```bash
pip install requests==2.32.3
```

Before the install is allowed, SafeDeps scans the project and fails the operation if blocking findings are found.

## Current status

SafeDeps is strongest today for Python and pip workflows.

| Area | Status |
| --- | --- |
| Python project scanning | Supported |
| `pip` runtime guard | Tested |
| `python -m pip` runtime guard | Tested |
| Local web UI | Tested for guard toggles and scan flows |
| npm scanning | Supported |
| npm runtime guard | Implemented, still being validated across environments |
| NuGet/.NET scanning | Supported |
| NuGet/.NET runtime flows | Implemented, still being validated across environments |
| Git submodule checks | Supported |

PyPI publishing is available:

```bash
pip install safedeps
```

The npm wrapper and .NET tool wrapper exist in this repository. npm and NuGet publishing are still being finalized.

## Install

For normal use:

```bash
python -m pip install safedeps
```

For local development from this repository:

```bash
git clone https://github.com/jaydemks/SafeDeps.git
cd SafeDeps
python -m pip install -e .[dev]
```

## Set up a project

Run setup once inside the project you want to protect:

```bash
safedeps setup .
```

Activate the guard in the current shell:

```bash
source .safedeps/activate.sh
```

PowerShell:

```powershell
python -m safedeps.cli setup .
. .\.safedeps\activate.ps1
```

After activation, guarded dependency operations are checked before they run.

## Scan

Run a local scan:

```bash
safedeps scan .
```

Fail on high or critical findings:

```bash
safedeps scan . --fail-on HIGH
```

Write scan artifacts to a folder:

```bash
safedeps scan . --out security-artifacts
```

Optional npm audit check:

```bash
safedeps scan . --online-audit
```

## UI

SafeDeps also has a local web UI:

```bash
safedeps ui --open-browser
```

The UI runs locally on `127.0.0.1` and opens a browser window. If the requested port is busy, SafeDeps tries nearby ports.

The UI is useful for scans, dependency inventory, guard controls, approvals, policy edits, baselines, and local intelligence files.

On Windows, you can create a desktop launcher:

```powershell
safedeps ui-shortcut
```

## What gets checked

SafeDeps can flag:

- unpinned Python dependencies
- floating npm versions such as `^`, `~`, `*`, or `latest`
- floating or range-based NuGet versions
- untrusted registries or package sources
- denied packages
- missing lockfiles
- direct URL dependencies that need review
- npm install lifecycle scripts
- suspicious package name patterns
- insecure Git submodule URLs
- expired exceptions
- local vulnerability feed matches
- optional metadata risk signals, when a metadata cache is provided

## Supported files

| Ecosystem | Files |
| --- | --- |
| Python / pip | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile.lock` |
| npm | `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `.npmrc` |
| NuGet / .NET | `*.csproj`, `Directory.Packages.props`, `packages.config`, `packages.lock.json`, `NuGet.Config`, `nuget.config` |
| Git | `.gitmodules` |

## Policy

SafeDeps creates a default policy at:

```text
.safedeps/policy.json
```

Minimal example:

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

Keep policies small at first. Start with pinned versions, trusted registries, deny packages, and lockfiles.

## Explain a finding

```bash
safedeps explain FLOATING_VERSION
```

This prints what the rule means and what SafeDeps expects you to change.

## Baselines and approvals

Create a baseline from a report:

```bash
safedeps baseline . \
  --report security-artifacts/safedeps-report.json \
  --output .safedeps/vuln-baseline.json
```

Add an expiring approval:

```bash
safedeps approve . \
  --manager npm \
  --rule FLOATING_VERSION \
  --package lodash \
  --file package.json \
  --expires 2026-12-31
```

Approvals should expire. Permanent suppressions are easy to forget.

## Local intelligence

SafeDeps can use local files for extra checks:

```text
.safedeps/vuln-feed.json
.safedeps/metadata-cache.json
```

The vulnerability feed can contain local package advisories. The metadata cache can be used for age, churn, and maintainer-change signals.

These files can be edited directly or from the UI.

## Reports

JSON report:

```bash
safedeps scan . --out security-artifacts
```

SARIF:

```bash
safedeps scan . --sarif security-artifacts/safedeps.sarif
```

CycloneDX:

```bash
safedeps scan . --cyclonedx security-artifacts/safedeps.cdx.json
```

SPDX:

```bash
safedeps scan . --spdx security-artifacts/safedeps.spdx.json
```

HTML:

```bash
safedeps scan . --html security-artifacts/safedeps-report.html
```

## CI

Minimal GitHub Actions example:

```yaml
name: SafeDeps

on:
  pull_request:
  push:
    branches: [main]

jobs:
  safedeps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: python -m pip install safedeps
      - run: safedeps scan . --fail-on HIGH --out security-artifacts
```

More CI examples are in:

```text
examples/ci/
```

## Pre-commit

The repository includes a pre-commit config:

```bash
pip install pre-commit
pre-commit install
```

The hook runs SafeDeps before commit.

## Check your setup

```bash
safedeps doctor .
```

This checks the local setup and warns about missing optional files or environment problems.

## Uninstall notes

If Auto Guard was enabled from the UI, turn it off before uninstalling.

You can also clean up guard hooks for the current project:

```bash
safedeps guard-cleanup .
```

Then uninstall:

```bash
python -m pip uninstall safedeps
```

## Development

Run tests:

```bash
python -m pytest
```

Useful release checks:

```bash
python scripts/check_versions.py
python scripts/release/preflight.py --expected-version 0.2.9
```

Version numbers should stay aligned across:

- `pyproject.toml`
- `safedeps/__init__.py`
- `packages/npm-wrapper/package.json`

Release tags should use:

```text
vX.Y.Z
```

## Security scope

SafeDeps is a preventive gate, not a guarantee that every package is safe.

Use it together with lockfiles, code review, vulnerability feeds, SBOM analysis, signed releases where supported, and CI policy enforcement.

SafeDeps is meant to add an early safety layer: before install, before commit, and before CI accepts a dependency change.
