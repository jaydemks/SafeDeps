# SafeDeps Known Limitations

SafeDeps is a preventive dependency policy gate. It reduces accidental supply-chain risk by blocking dependency changes that violate local policy before install, commit, or CI acceptance.

SafeDeps does not prove that a package is safe, does not replace code review, and does not replace tools such as `pip-audit`, `osv-scanner`, sandboxing, endpoint security, or registry-side malware detection.

## Current Reliability Profile

| Area | Status | Notes |
| --- | --- | --- |
| Python project scanning | Stable | Covered by the current test suite and examples. |
| `pip` runtime guard | Stable | Includes shell wrappers and interpreter-level guard behavior. |
| `python -m pip` runtime guard | Stable | Intended to block common shell-wrapper bypasses. |
| Local web UI | Stable for core guard flows | Guard setup, toggles, scan flow, and dependency tables need continued visual QA. |
| npm scanning | Supported | Manifest and lockfile checks are in scope. |
| npm runtime guard | Limited | First blocking slice validated for Node 22 on Ubuntu Bash and Windows PowerShell/CMD; no broad production-grade runtime claim yet. |
| NuGet/.NET scanning | Supported | Project, props, config, and lockfile checks are in scope. |
| NuGet/.NET runtime guard | Not claimed | Scan/CI validation is strong, but SafeDeps does not yet install a `dotnet` command interceptor. |

## Important Non-Guarantees

- A user with local admin access can disable shell hooks, wrappers, startup hooks, or CI configuration.
- A malicious package may still be installed if it is explicitly approved by policy or by a maintainer exception.
- Runtime guards are best-effort local controls; CI enforcement is still required for shared repositories.
- Registry metadata, vulnerability feeds, and ecosystem provenance signals can be incomplete or delayed.
- SafeDeps cannot determine whether a legitimate maintainer intentionally shipped malicious code.

## Current Engineering Risks

- The test suite still needs to be split into smaller unit, guard, integration, e2e, and UI areas.
- npm needs broader Node/npm-version and package-behavior e2e validation before broad runtime claims.
- NuGet needs a dedicated `dotnet` command interception design before it should be described as runtime protection.
- CI still needs broader Node/npm matrices before npm can be promoted beyond the first blocking slice.
- UI templates and guard wrapper templates need continued decomposition.
