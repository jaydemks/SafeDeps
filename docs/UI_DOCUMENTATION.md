# SafeDeps UI Documentation

This document explains how to open and use the SafeDeps web UI, including every field and button.

## 1. Open The UI

Prerequisites:

- Run commands from the repository root.
- Use an active Python environment where SafeDeps is installed (`pip install .` or `pip install -e .[dev]`).

Start UI:

```bash
safedeps ui . --open-browser
```

Alternative (module form):

```bash
python -m safedeps.cli ui . --open-browser
```

Default URL:

- `http://127.0.0.1:8765/`

If port `8765` is busy:

```bash
safedeps ui . --host 127.0.0.1 --port 8877
```

Then open:

- `http://127.0.0.1:8877/`

Important:

- Open exactly `/` (root path). The UI only serves the root page (`GET /`).

## 2. UI Layout Overview

The page contains these sections:

1. Setup status + `Setup Project Guard`
2. Scan form + `Run Scan`
3. Rule explanation form + `Explain Rule`
4. Baseline generation form + `Create Baseline`
5. Approval form + `Add/Update Approval`
6. Intelligence editor + `Save Intelligence Files` / `Create Starter Templates`
7. Results area (status/notice/error)
8. Pip install guard panel
9. Findings table (`Use For Approval` action per finding)

## 3. Setup Section

### Setup status

- Read-only status message at top.
- Shows whether project guard is configured.

### Button: `Setup Project Guard`

Action:

- Creates/updates SafeDeps setup files in `.safedeps/`.
- Prepares guarded `pip` wrappers and activation script.

Backend endpoint:

- `POST /setup`

## 4. Scan Section

### Field: `Project path`

- Target folder to scan.
- Default: current path passed to `safedeps ui`.

### Field: `Fail on`

- Severity threshold used to fail scan.
- Allowed values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

### Field: `Output dir`

- Output directory for generated artifacts.
- Default: `security-artifacts`.

### Field: `Policy file (optional)`

- Custom policy path.
- If empty, default policy resolution is used.

### Field: `SARIF path (optional)`

- If set, writes SARIF file to this path.

### Field: `CycloneDX path (optional)`

- If set, writes CycloneDX SBOM JSON to this path.

### Field: `SPDX path (optional)`

- If set, writes SPDX JSON to this path.

### Field: `HTML path (optional)`

- If set, writes HTML report to this path.

### Checkbox: `Online audit`

- Enables ecosystem audit commands where supported.
- May require network/tooling available in your environment.

### Button: `Run Scan`

Action:

- Runs scan pipeline with the selected options.
- Produces findings, SBOM, and optional exports.

Backend endpoint:

- `POST /scan`

## 5. Rule Explanation Section

### Field: `Explain rule`

- Finding rule id to explain.
- Example: `FLOATING_VERSION`.

### Button: `Explain Rule`

Action:

- Returns text explanation for the requested rule.

Backend endpoint:

- `POST /explain`

## 6. Baseline Section

### Field: `Report path`

- Input report JSON path.
- Default: `security-artifacts/safedeps-report.json`.

### Field: `Baseline output path`

- Destination path for generated baseline JSON.
- Default: `.safedeps/vuln-baseline.json`.

### Button: `Create Baseline`

Action:

- Reads findings from report JSON.
- Writes suppression entries into baseline file.

Backend endpoint:

- `POST /baseline`

## 7. Approval Section

### Field: `Baseline file`

- Baseline JSON path to edit.
- Default: `.safedeps/vuln-baseline.json`.

### Field: `Manager`

- Dependency manager for suppression entry.
- Typical values: `npm`, `pip`, `nuget`, `git`.

### Field: `Rule`

- Rule id for suppression entry.
- Example: `FLOATING_VERSION`.

### Field: `Package (optional)`

- Package name filter for suppression.

### Field: `File (optional)`

- File path filter for suppression.

### Field: `Expires (YYYY-MM-DD)`

- Mandatory expiration date.
- Must be valid ISO date, e.g. `2026-12-31`.

### Button: `Add/Update Approval`

Action:

- Inserts or updates an approval entry in baseline.

Backend endpoint:

- `POST /approve`

Validation notes:

- `manager` and `rule` are required.
- `expires` must be a valid date.

### Button in findings table: `Use For Approval`

Action:

- Prefills `Manager`, `Rule`, `Package`, `File` in approval form.
- Scrolls to approval form automatically.

## 8. Intelligence Section

### Field: `Local vulnerability feed JSON (.safedeps/vuln-feed.json)`

- Raw JSON editor for local vulnerability intelligence.

### Field: `Local metadata cache JSON (.safedeps/metadata-cache.json)`

- Raw JSON editor for local package metadata signals.

### Button: `Save Intelligence Files`

Action:

- Validates both JSON blocks.
- Saves to:
  - `.safedeps/vuln-feed.json`
  - `.safedeps/metadata-cache.json`

Backend endpoint:

- `POST /intelligence` with `intel_action=save`

### Button: `Create Starter Templates`

Action:

- Creates template intelligence files when missing.
- Loads templates into editor.

Backend endpoint:

- `POST /intelligence` with `intel_action=template`

Validation notes:

- Empty JSON blocks are rejected.
- JSON must be valid and object-shaped.

## 9. Results Area

Possible result panels:

- Status panel (pass/fail + counts + output path)
- Notice panel (informational)
- Error panel (validation/runtime errors)

## 10. Pip Guard Panel

Shown after scan results.

- If blocking pip findings exist at selected threshold: error panel with list.
- Otherwise: notice panel saying no blocking pip findings.

## 11. Findings Table

Columns:

- `Severity`
- `Manager`
- `Rule`
- `Package`
- `File`
- `Message`
- `Action`

Behavior:

- Sorted by severity (highest first).
- Each row has `Use For Approval` to prefill approval form.

## 12. Common Issues

### JSON `{ "ok": false, "detail": "not_found" }`

- Usually means you are not hitting the SafeDeps UI root endpoint.
- Open `http://127.0.0.1:8765/` (or chosen port) exactly.

### Blank page + browser console extension errors

- Errors like message channel closed are often from browser extensions.
- Retry in private/incognito window or another browser.

### Port conflict

- Run on another port:
  - `safedeps ui . --host 127.0.0.1 --port 8877`

