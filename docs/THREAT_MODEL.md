# SafeDeps Threat Model

## Goal

SafeDeps is a preventive dependency policy gate. It makes risky dependency changes harder to introduce by accident, by scripts, or by AI coding agents.

## Non-Goals

SafeDeps does not prove that every package is safe. It does not replace sandboxing, endpoint security, registry-side malware detection, vulnerability scanners, or human review.

## Protected Assets

- Project dependency manifests.
- Lockfiles.
- Developer workstation package manager commands.
- CI dependency changes.
- Local SafeDeps policy and approval files.

## Trust Boundaries

- Local shell configuration.
- Python interpreter startup hook.
- Generated package-manager wrappers.
- Package registries and vulnerability feeds.
- Repository policy files.
- CI runners and workflow configuration.

## Attack Scenarios

| Scenario | Covered? | Notes |
| --- | --- | --- |
| Unpinned dependency added by an AI agent | Yes | Blocked when policy requires exact versions. |
| Known blocked package | Yes | Covered when present in local policy, denylist, or available vulnerability data. |
| Direct URL dependency | Yes | Must be blocked or explicitly approved by policy. |
| Git URL dependency | Yes | Must require a pinned commit or an explicit approval path. |
| Dependency confusion | Partial | Needs private package policy and registry/source restrictions. |
| Shell-wrapper bypass | Partial | Interpreter hooks reduce bypass risk; e2e coverage must continue expanding. |
| User disables guard | No | This must be visible in status, doctor output, or CI checks. |
| Malicious maintainer release | Partial | Package-age, publisher, provenance, and vulnerability signals can reduce but not eliminate risk. |
| Compromised CI workflow | No | SafeDeps depends on CI configuration being reviewed and protected. |

## Security Claims SafeDeps Can Make

- Enforces dependency policy before dependency changes are accepted.
- Blocks unapproved or unpinned dependency changes when configured to do so.
- Produces reviewable reports and security artifacts for CI and maintainers.
- Provides best-effort local runtime guards for supported package-manager commands.

## Security Claims SafeDeps Must Not Make

- It does not guarantee that dependencies are safe.
- It does not make installs impossible to bypass on a fully controlled workstation.
- It does not replace ecosystem-native security scanning.
- It is not a malware detector by itself.
