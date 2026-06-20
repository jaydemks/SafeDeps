# SafeDeps Policy

SafeDeps policy describes which dependency changes are allowed before install, commit, or CI acceptance.

## Core Principles

- Prefer exact versions for runtime dependencies.
- Require lockfiles where the ecosystem supports them.
- Block direct URLs and Git URLs unless explicitly approved.
- Keep exceptions narrow, documented, and time-limited where possible.
- Treat package-manager behavior as ecosystem-specific, but keep policy decisions consistent.

## Recommended Defaults

| Control | Recommended default | Reason |
| --- | --- | --- |
| Unpinned versions | Block | Floating versions make review and rollback harder. |
| Direct URLs | Block or require approval | Source identity and repeatability are weaker. |
| Git URLs | Require commit pin or approval | Branch and tag targets can move. |
| Missing lockfile | Warn or block by project type | Lockfiles improve reproducibility. |
| Denylisted packages | Block | Maintainer-defined hard stop. |

## Exception Expectations

Approvals should include a clear reason, the package or source being approved, and enough context for a future maintainer to decide whether the approval is still valid.
