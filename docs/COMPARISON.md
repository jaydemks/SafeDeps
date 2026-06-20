# SafeDeps Comparison

SafeDeps is a dependency policy gate. It is designed to stop risky dependency changes before they become installed packages, committed manifests, or accepted CI changes.

It is not a malware detector, sandbox, package reputation oracle, or replacement for vulnerability scanners. It works best beside those tools.

## Positioning

| Tool category | Primary job | Where SafeDeps fits |
| --- | --- | --- |
| Vulnerability scanners | Detect known vulnerable package versions. | SafeDeps can fail scans on configured vulnerability intelligence, but its core value is policy enforcement before dependency changes land. |
| Registry or malware scanners | Detect malicious packages at registry or artifact level. | SafeDeps does not claim malware certainty; it blocks suspicious dependency patterns such as unpinned versions, direct URLs, untrusted registries, denied packages, and risky metadata signals. |
| Lockfile and SBOM tools | Produce dependency inventory and provenance artifacts. | SafeDeps emits reports and SBOM formats, then uses policy gates to decide whether a change should proceed. |
| CI dependency review | Catch dependency changes during pull requests. | SafeDeps also runs locally before install/update, which helps catch risky changes before they reach CI. |
| Runtime shell wrappers | Intercept package-manager commands. | SafeDeps combines shell wrappers with an interpreter-level pip guard for common Python bypasses. |

## Strongest Current Claim

SafeDeps is strongest today for Python/pip:

- project scanning;
- `pip` and `python -m pip` guard paths;
- policy-driven blocking for unpinned installs, denied packages, untrusted registries, direct URLs, and known vulnerability signals;
- local UI workflows for scan and guard setup;
- CI-friendly JSON, HTML, SARIF, CycloneDX, and SPDX outputs.

## Experimental Areas

npm and NuGet scanning are supported, but runtime protection remains experimental until their OS, shell, and package-manager e2e matrices are green.

## When To Use SafeDeps

Use SafeDeps when:

- developers or AI coding agents can add dependencies quickly;
- you want local pre-install friction before risky dependency changes happen;
- CI should enforce the same policy as local development;
- dependency review needs clear findings, fixes, baselines, and report artifacts.

Do not use SafeDeps as the only supply-chain defense. Pair it with lockfile review, vulnerability scanning, package provenance checks, CI protections, and human review for high-risk changes.
