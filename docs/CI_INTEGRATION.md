# SafeDeps CI Integration

CI must enforce dependency policy independently from local workstation guards.

## Minimum Checks

- Install the package with development dependencies.
- Run formatting and lint checks.
- Run type checking.
- Run tests with coverage.
- Build wheel and source distribution.
- Run SafeDeps against known safe and unsafe fixtures.
- Upload security artifacts where useful.

## Recommended Command

```bash
make checks
```

## Local Example Scans

The repository includes scan fixtures that can be exercised without contacting package registries:

```bash
safedeps scan examples/safe-project --fail-on HIGH --out examples/safe-project/security-artifacts
```

The safe fixture should pass. It includes pinned Python, Node, and .NET dependencies with committed lockfiles.

```bash
safedeps scan examples/bad-project --fail-on HIGH --out examples/bad-project/security-artifacts
```

The bad fixture should fail. It includes untrusted registries, floating versions, an npm install script, and a floating NuGet `PackageReference`.

Use these fixtures as scan-supported examples in CI. Python/pip runtime guard behavior has dedicated e2e coverage; npm and NuGet/.NET runtime guard behavior remains experimental until the e2e matrices below are mandatory and green.

## Recommended Expansion

- Matrix across Linux, Windows, and macOS.
- Python 3.10, 3.11, 3.12, and 3.13.
- Dedicated pip e2e workflow.
- Dedicated npm e2e workflow before npm runtime guard is called stable.
- Dedicated NuGet e2e workflow before NuGet runtime guard is called stable.
- CodeQL, Dependency Review, Dependabot, and OpenSSF Scorecard.

## Current CI Coverage

SafeDeps now has these release/stabilization gates:

- `quality.yml`: unit test matrix across Ubuntu, Windows, macOS and Python 3.10-3.13.
- `quality.yml`: full `make checks` gate on Ubuntu with lint, typecheck, coverage, build, twine check, and smoke checks.
- `e2e-pip.yml`: real guarded pip install flows across Bash on Ubuntu/macOS, PowerShell on Windows, and CMD on Windows.
- `e2e-npm.yml`: required scan validation across Ubuntu/Windows and Node 20/22, plus diagnostic runtime guard jobs marked experimental.
- `e2e-nuget.yml`: required NuGet scan validation across Ubuntu/Windows with .NET 8 SDK.
- `security.yml`: CodeQL, Dependency Review, and OpenSSF Scorecard.

## Matrix Status

| Area | Required coverage | Current status |
| --- | --- | --- |
| OS matrix | Ubuntu, Windows, macOS | Covered by `quality.yml`; pip e2e covers Ubuntu/macOS Bash and Windows PowerShell/CMD. |
| Python matrix | Python 3.10, 3.11, 3.12, 3.13 | Covered by `quality.yml` and `e2e-pip.yml`. |
| Shell matrix | Bash, PowerShell, CMD | Covered for pip guard e2e; npm runtime jobs are diagnostic/experimental. |
| pip versions | Latest plus representative older pip | Covered in `e2e-pip.yml` with latest and 23.3.2. |
| npm versions | Node 20 and 22 scan validation | Covered for scan validation in `e2e-npm.yml`; runtime guard remains experimental. |
| NuGet/.NET SDK | .NET 8 SDK scan validation | Covered for scan validation in `e2e-nuget.yml`; runtime guard remains experimental. |
| Security workflows | CodeQL, Dependency Review, Scorecard | Covered by `security.yml`. |

The stable CI claim is intentionally narrower than the full product ambition: Python/pip runtime protection is covered by real e2e workflows; npm and NuGet are scan-supported until their runtime guard jobs become mandatory and non-experimental.

The pip e2e workflow checks:

- project guard setup;
- shell activation;
- blocked unpinned `pip install six`;
- allowed pinned `pip install six==1.17.0`;
- blocked unpinned `python -m pip install six` through the activated shell wrapper.

npm and NuGet remain experimental until equivalent e2e workflows cover their package-manager behavior across supported operating systems.

The npm validation workflow currently checks:

- floating npm dependency scan failure;
- pinned npm dependency scan pass with lockfile;
- `npm ci` lockfile smoke behavior;
- experimental runtime guard checks for Bash, PowerShell, and CMD.

The NuGet validation workflow currently checks:

- floating or range `PackageReference` scan failure;
- pinned `PackageReference` scan pass;
- `Directory.Packages.props` central package management scan pass.

## Promotion Gates Still Missing

npm runtime support should not be promoted until CI includes:

- npm runtime guard jobs are mandatory instead of diagnostic/continue-on-error;
- npm lockfile v2/v3 coverage is explicit;
- workspace coverage is included.

NuGet runtime support should not be promoted until CI includes:

- `dotnet add package` blocked when unsafe/unapproved;
- allowed pinned `PackageReference` flows;
- `packages.lock.json` or restore-lock behavior where applicable;
- runtime guard tooling for `dotnet add package`, if the project chooses to support it.
