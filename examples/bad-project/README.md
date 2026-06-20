# SafeDeps Bad Project

This fixture is designed to fail a SafeDeps scan. It keeps the risky patterns small and visible so users can compare them with `examples/safe-project`.

## Expected Findings

- Python: untrusted package index and floating `requests>=2`.
- Node: untrusted `.npmrc`, `latest` and caret versions, plus an install lifecycle script.
- .NET: floating `Newtonsoft.Json` version in `Bad.csproj`.
- Git: insecure submodule URL.
- Lockfiles: intentionally missing for Python, Node, and .NET.

## Try It

From the repository root:

```bash
safedeps scan examples/bad-project --fail-on HIGH --out examples/bad-project/security-artifacts
```

For a local checkout where SafeDeps is not installed yet:

```bash
python -m pip install -e .
python -m safedeps.cli scan examples/bad-project --fail-on HIGH --out examples/bad-project/security-artifacts
```

The command is expected to exit non-zero because this fixture contains HIGH and CRITICAL findings. npm and NuGet/.NET runtime blocking are still experimental; this project demonstrates scan behavior, not a stable runtime guard claim.
