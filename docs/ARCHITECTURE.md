# SafeDeps Architecture

SafeDeps should be organized around a small core and ecosystem-specific adapters.

## Intended Boundaries

| Area | Responsibility |
| --- | --- |
| CLI | Parse arguments and orchestrate commands. |
| Core models | Represent packages, findings, scan results, policy decisions, and severity. |
| Policy | Load policy, evaluate decisions, and manage approvals. |
| Ecosystem adapters | Detect projects, parse manifests and lockfiles, and inspect install commands. |
| Verifiers | Produce findings from package targets and scan context. |
| Guard | Install, activate, deactivate, and test local runtime protections. |
| Reporters | Convert scan results into SARIF, CycloneDX, SPDX, HTML, or text output. |
| UI | Render and serve the local product surface. |

## Rules

- CLI code should not contain security decision logic.
- Parsers should not write files.
- Verifiers should not mutate global state.
- Reporters should not decide severity.
- Guard code should not know report formats.
- Filesystem and shell interactions should be isolated and tested.

## Refactor Direction

The current codebase has already been split from an earlier monolithic CLI, but compatibility exports still keep `safedeps.cli` broad. The next refactor should move toward explicit `core`, `policy`, `ecosystems`, `verifiers`, `guard`, `reporters`, and `ui` packages while preserving existing command behavior.
