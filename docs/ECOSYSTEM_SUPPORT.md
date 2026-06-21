# SafeDeps Ecosystem Support

This matrix distinguishes supported scanning from runtime guard maturity. Runtime guard maturity requires repeatable e2e validation across operating systems, shells, and package-manager versions.

| Ecosystem | Scanning | Runtime guard | Maturity |
| --- | --- | --- | --- |
| Python/pip | Supported | Supported | Stable |
| Poetry lockfiles | Supported | Not claimed | Stable for lockfile scan validation |
| npm | Supported | Experimental | Scan-supported only until e2e matrix is green |
| NuGet/.NET | Supported | Experimental | Scan-supported only until e2e matrix is green |
| Git submodules | Supported | Not applicable | Stable for scan checks |

## Promotion Rule

An ecosystem should only move from experimental to stable after:

- representative e2e install-block and install-allow tests are green;
- Linux, Windows, and macOS behavior is documented or explicitly scoped;
- wrapper, shell, and direct command bypass cases are tested where relevant;
- README and UI wording match the tested behavior.

## Current Priority

Python/pip remains the reference quality bar. npm and NuGet should be validated against that bar before adding larger feature work.

Poetry lockfile scan validation is now part of the Python ecosystem evidence. SafeDeps validates real `poetry lock` output across Poetry `1.7.1`, `1.8.5`, `2.0.1`, `2.1.4`, `2.2.1`, `2.3.4`, and `2.4.1`. This does not promote Poetry install/update runtime interception; the stable claim is lockfile scanning.

## Current npm/NuGet Claim

SafeDeps may parse npm and NuGet manifests and lockfiles, and experimental wrappers/tooling exist in the repository. The stable claim is limited to scanning. Runtime blocking for npm and NuGet must remain experimental until dedicated e2e workflows validate install-block, install-allow, shell behavior, and package-manager version behavior.

Current validation status:

- npm has required scan-validation jobs for Ubuntu/Windows and Node 20/22, plus diagnostic runtime guard jobs that remain experimental.
- NuGet has required scan-validation jobs for Ubuntu/Windows and .NET 8 SDK.
- NuGet runtime guard support is not promoted; `dotnet add package` needs dedicated guard tooling and e2e coverage before that claim can change.
