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
| Advisory severity threshold | `LOW` | Known advisory signals should be visible unless policy intentionally raises the bar. |
| Metadata risk severity | `MEDIUM` | Local metadata signals are review prompts, not proof of compromise. |

## Local Intelligence Controls

SafeDeps can read `.safedeps/vuln-feed.json` and `.safedeps/metadata-cache.json` during scans.

- `advisory_severity_threshold` controls which local advisory severities are reported.
- `metadata_risk_severity` controls the severity assigned to enabled metadata risk findings.
- `enable_package_age_checks`, `enable_publisher_churn_checks`, `enable_maintainer_change_checks`, `enable_repository_link_checks`, and `enable_download_anomaly_checks` turn metadata checks on when a local cache is available.
- Online checks should remain optional; deterministic local feeds and fixtures are the release gate.

## Exception Expectations

Approvals should include a clear reason, the package or source being approved, and enough context for a future maintainer to decide whether the approval is still valid.
