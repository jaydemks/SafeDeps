# SafeDeps Safe Project

This fixture is intentionally boring: all versions are exact and each ecosystem has a lockfile so `safedeps scan` can run offline.

## What It Covers

- Python: `requirements.txt` and `requirements.lock` both pin `requests==2.32.3`.
- Node: `package.json` pins `lodash` and `package-lock.json` is committed.
- .NET: `Safe.csproj` pins `Newtonsoft.Json` and `packages.lock.json` is committed.

## Try It

From the repository root:

```bash
safedeps scan examples/safe-project --fail-on HIGH --out examples/safe-project/security-artifacts
```

For a local checkout where SafeDeps is not installed yet:

```bash
python -m pip install -e .
python -m safedeps.cli scan examples/safe-project --fail-on HIGH --out examples/safe-project/security-artifacts
```

The scan should pass without contacting package registries. Runtime guards are strongest for Python/pip. npm and NuGet/.NET runtime blocking remain experimental; use these Node and .NET files as scan-supported examples.
