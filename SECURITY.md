# Security Policy

## Supported Versions

SafeDeps is pre-1.0. Security fixes are expected to target the latest released version unless a maintainer explicitly announces otherwise.

## Reporting A Vulnerability

Please report suspected vulnerabilities privately through GitHub security advisories for the repository when available. If advisories are unavailable, contact the maintainer directly and avoid publishing exploit details until a fix or mitigation is available.

Include:

- affected SafeDeps version;
- operating system and shell;
- package manager and version;
- reproduction steps;
- expected policy behavior;
- observed bypass or failure mode.

## Scope

In scope:

- policy bypasses;
- runtime guard bypasses for documented supported flows;
- unsafe report or artifact generation;
- incorrect approval handling;
- CI enforcement gaps caused by SafeDeps behavior.

Out of scope:

- bypasses requiring full control of the local machine and intentional removal of SafeDeps controls;
- vulnerabilities in third-party package managers or registries;
- malicious packages that SafeDeps has no configured policy, feed, or verifier signal to detect.
