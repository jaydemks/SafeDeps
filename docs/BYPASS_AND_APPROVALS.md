# SafeDeps Bypass And Approvals

SafeDeps is designed to make risky dependency changes visible and harder to introduce by accident. It is not designed to stop a trusted local user who intentionally disables controls.

## Common Bypass Paths

| Path | Expected handling |
| --- | --- |
| Disable shell aliases or functions | Doctor/status should make inactive protection visible. |
| Call package manager through a different interpreter | Interpreter hook and project/global scope tests should cover supported Python paths. |
| Use another machine or CI job without SafeDeps | CI workflows must enforce policy independently. |
| Edit manifests manually | Pre-commit and CI scans must catch policy violations. |
| Use direct URLs, Git URLs, or alternate registries | Policy should block or require explicit approval. |

## Approval Rules

- Approvals should be narrow.
- Approvals should include a human-readable reason.
- Approvals should be reviewed during releases and dependency refreshes.
- High-risk approvals should expire or be revalidated.

## Reviewer Checklist

- Is the requested dependency pinned?
- Is the source registry expected?
- Is there a lockfile or reproducible install path?
- Is the approval reason specific enough for a later audit?
- Does CI enforce the same policy as local development?
