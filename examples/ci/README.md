# SafeDeps CI Templates

This folder contains ready-to-copy CI templates for running SafeDeps as a dependency security gate.

## Included templates

- GitHub Actions: `examples/ci/github/safedeps.yml`
- GitLab CI: `examples/ci/gitlab/.gitlab-ci.yml`
- Azure Pipelines: `examples/ci/azure/azure-pipelines.yml`

## What each template does

- Installs SafeDeps (`pip install .` for local repo usage)
- Runs `safedeps scan` with `--fail-on HIGH`
- Exports compliance artifacts:
  - `safedeps-report.json`
  - `safedeps-sbom.json`
  - `safedeps.sarif`
  - `safedeps.cdx.json`
  - `safedeps.spdx.json`
- Publishes artifacts in the CI system

## Recommended policy baseline

Ensure `.safedeps/policy.json` exists in your repository. You can initialize it with:

```bash
safedeps init
```
