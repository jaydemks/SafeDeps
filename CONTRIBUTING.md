# Contributing

SafeDeps is a security-focused tool, so changes should be small, reviewable, and backed by tests.

## Development Setup

```bash
python -m pip install -e ".[dev]"
```

## Local Checks

```bash
make checks
```

For faster iteration:

```bash
make format
make test
```

## Test Expectations

- Add regression tests for bug fixes.
- Keep tests isolated with temporary directories where possible.
- Avoid network-dependent tests in the default suite.
- Keep npm and NuGet runtime behavior marked experimental until e2e coverage is green.

## Documentation Expectations

Update README and docs when behavior, guarantees, limitations, or command output changes.
