# SafeDeps UI - Practical User Guide

This guide explains the UI in plain language: what to type, what to click, and what happens next.

## 1. How To Open The UI

From your project folder, run:

```bash
safedeps ui . --open-browser
```

If the browser does not open automatically, open this URL manually:

- `http://127.0.0.1:8765/`

If port `8765` is already in use, run:

```bash
safedeps ui . --host 127.0.0.1 --port 8877
```

Then open:

- `http://127.0.0.1:8877/`

Important:

- Open the root path `/` (example: `http://127.0.0.1:8765/`).

## 2. What You See On The Page

The UI is split into blocks:

1. `Setup Project Guard`
2. `Run Scan`
3. `Explain Rule`
4. `Create Baseline`
5. `Add/Update Approval`
6. `Intelligence Settings`
7. Results area (status, errors, findings table)

## 3. Setup Project Guard

### What it is for

Prepares your project so `pip install` can be protected by SafeDeps checks.

### What to do

- Click `Setup Project Guard`.

### What happens

- SafeDeps creates/updates files in `.safedeps/`.
- The UI shows a confirmation message.

When to use it:

- First time on a new project.
- Any time you think setup files were removed or changed.

## 4. Run Scan Section (Main Workflow)

### Field: Project path

What to enter:

- The folder you want to scan.

Examples:

- `.` -> scans the current folder.
- `examples/bad-project` -> scans that demo project.

### Field: Fail on

What it means:

- Sets the severity threshold that makes the scan fail.

Example:

- If you choose `HIGH`, `HIGH` and `CRITICAL` findings fail the scan.
- If you choose `CRITICAL`, a `HIGH` finding does not fail the scan.

### Field: Output dir

What to enter:

- Folder where reports and SBOM files will be saved.

Examples:

- `security-artifacts` (default)
- `security-artifacts-mytest` to keep outputs separate

### Field: Policy file (optional)

What to enter:

- Path to a custom policy file.

Example:

- `.safedeps/policy.json`

If left empty:

- SafeDeps uses the default project policy behavior.

### Optional export fields

- `SARIF path (optional)`
- `CycloneDX path (optional)`
- `SPDX path (optional)`
- `HTML path (optional)`

Useful examples:

- `security-artifacts/safedeps.sarif`
- `security-artifacts/safedeps.cdx.json`
- `security-artifacts/safedeps.spdx.json`
- `security-artifacts/safedeps-report.html`

If left empty:

- That export format is not generated.

### Checkbox: Online audit

Turn it on when:

- You want extra audit checks that use available online ecosystem data.

Leave it off when:

- You want local/offline behavior.

### Button: Run Scan

What happens after click:

- The scan starts.
- You get `PASS` or `FAIL`.
- You see finding count and details table.
- Files are written to the output folder.

## 5. Explain Rule

### Field: Explain rule

What to enter:

- The rule code you want to understand.

Examples:

- `FLOATING_VERSION`
- `MISSING_LOCKFILE`
- `UNTRUSTED_REGISTRY`

### Button: Explain Rule

What happens:

- The UI shows a plain explanation of that rule.

When to use it:

- When a finding appears and you want to understand why.

## 6. Create Baseline

### What it is for

Creates a baseline file from an existing scan report.

### Field: Report path

What to enter:

- The report JSON to read.

Example:

- `security-artifacts/safedeps-report.json`

### Field: Baseline output path

What to enter:

- Where to save the baseline file.

Example:

- `.safedeps/vuln-baseline.json`

### Button: Create Baseline

What happens:

- UI reads findings from the report.
- UI writes suppression entries to baseline output.

## 7. Add/Update Approval

Use this section to add targeted, expiring exceptions.

### Field: Baseline file

Example:

- `.safedeps/vuln-baseline.json`

### Field: Manager

Examples:

- `npm`
- `pip`
- `nuget`
- `git`

### Field: Rule

Example:

- `FLOATING_VERSION`

### Field: Package (optional)

Example:

- `lodash`

If left empty:

- Exception is less specific.

### Field: File (optional)

Example:

- `package.json`

### Field: Expires (YYYY-MM-DD)

Valid example:

- `2026-12-31`

If date is invalid:

- UI returns an error.

### Button: Add/Update Approval

What happens:

- Entry is added (or updated) in the baseline file.

### Button in findings table: Use For Approval

Recommended usage:

1. Run a scan.
2. In a finding row, click `Use For Approval`.
3. `Manager`, `Rule`, `Package`, and `File` are auto-filled.
4. Enter only `Expires`.
5. Click `Add/Update Approval`.

## 8. Intelligence Settings

Use this area to manage local JSON intelligence without leaving the UI.

### Field: Local vulnerability feed JSON

Linked file:

- `.safedeps/vuln-feed.json`

What to do:

- Paste or edit valid vulnerability JSON.

### Field: Local metadata cache JSON

Linked file:

- `.safedeps/metadata-cache.json`

What to do:

- Paste or edit valid metadata JSON.

### Button: Save Intelligence Files

What happens:

- UI validates both JSON blocks.
- If valid, files are saved.
- If invalid, you get an error.

### Button: Create Starter Templates

What happens:

- UI creates starter JSON templates when files are missing.
- Good for first-time setup.

## 9. How To Read Results

### PASS / FAIL

- `PASS`: no blocking findings at your `Fail on` threshold.
- `FAIL`: one or more blocking findings at that threshold.

### Pip install guard panel

- Shows whether blocking `pip` findings exist at the selected threshold.

### Findings table

Each row shows:

- Severity
- Manager
- Rule
- Package
- File
- Message

Tip:

- Review `CRITICAL` and `HIGH` findings first.

## 10. Recommended Quick Flow

1. Click `Setup Project Guard`.
2. Set `Project path` to `.`.
3. Keep `Fail on` as `HIGH`.
4. Click `Run Scan`.
5. If findings appear:
   - use `Explain Rule` to understand them;
   - if needed, use `Use For Approval` + `Add/Update Approval` with an expiration date.
6. Run `Run Scan` again to confirm the final result.

## 11. Common Problems

### You see `{ "ok": false, "detail": "not_found" }`

Usually means you are not hitting the SafeDeps root page or another service is on that port.

- Open `http://127.0.0.1:8765/` (with trailing slash).
- If needed, switch port (`--port 8877`).

### Blank page with browser console extension errors

Often caused by browser extensions, not SafeDeps.

- Try private/incognito mode.
- Or try a different browser.
