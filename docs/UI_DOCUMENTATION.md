# SafeDeps UI - Practical User Guide

This guide explains the current UI workflow in plain language.

## Open The UI

Recommended command from the project root:

```bash
safedeps ui .
```

Behavior:

- `safedeps ui .` opens the UI on the current project root.
- `safedeps ui` opens a dedicated SafeDeps workspace at `~/.safedeps/workspace`.
- Use an explicit path (`safedeps ui .` or `safedeps ui C:\path\project`) when you want the UI to scan/protect a project.
- Default start port is `5200` and SafeDeps auto-tries next local ports if one is blocked.
- On Windows you can create a desktop launcher with `safedeps ui-shortcut`.

## Light/Dark Theme

- Click `Theme` in the top-right corner.
- The UI remembers your choice in the browser.

## Dashboard Layout

The UI is organized as a single-page dashboard. Navigation does not reload the browser page.

- The left sidebar expands to show icon + section name, or collapses to icon-only mode.
- The SafeDeps logo is shown in the lower sidebar area.
- Main pages are `Overview`, `Run Scan`, `Console`, `Exceptions`, `Policy`, and `Intelligence`.
- `Run Scan` contains the scan form, dependency quick actions, and guided dependency management in one workflow page.
- Path values wrap inside their panels instead of overflowing.
- Forms, buttons, toggles, tables, scrollbars, and loading states use the same glass-style visual system.
- The search field filters visible content inside the active page.

## Auto Guard + Scope (PowerShell)

In `Overview` you have compact cards and controls for:

- setup status
- auto-guard status
- runtime Python
- current shell status
- `Auto ON` / `Auto OFF`
- `Project` / `Global`

What it does:

- `Auto ON`: adds SafeDeps activation to your PowerShell profile (new PowerShell sessions load guard automatically).
- `Auto OFF`: removes that profile hook.
- `Project`: guard applies only in project context.
- `Global`: guard applies globally.

Reinstall/upgrade note:

- After reinstalling SafeDeps, run `safedeps setup .` once in your target project.
- The UI now re-checks effective guard hooks and aligns the toggle with real state.

## Recommended Workflow

1. Open `Overview` and click `Setup Guard` (first time per project).
2. Open `Run Scan`, keep `Project path` as `.` and `Fail on` as `HIGH`.
3. Click `Run Scan`.
4. Open `Dependencies` and review quick actions.
5. Use `Manage`, `Exceptions`, or `Policy` as needed.
6. Re-run scan to confirm result.

Note:

- By default, repository sample fixtures under `examples/` are excluded from scans via policy (`exclude_paths`) to keep real-project checks cleaner.

## Run Scan

### Project path

- Folder to scan.
- Example: `.` or `examples/bad-project`.

### Fail on

- Threshold that marks scan as failed.
- Example: `HIGH` means `HIGH` and `CRITICAL` findings block.

### Output dir

- Where report files are saved.
- Example: `security-artifacts`.

### Policy file (optional)

- Custom policy file path.
- Example: `.safedeps/policy.json`.

### Optional export paths

- SARIF, CycloneDX, SPDX, HTML.
- If left empty, that export is not produced.

### Online audit

- Enables extra online audit checks when available.

### Run Scan

After click:

- You get `PASS` or `FAIL`.
- Findings table appears.
- Dependency table is populated.

## Dependencies

This is the central user-friendly table.

Columns:

- Manager
- Package
- Version
- Worst Severity
- Status
- Rules
- Quick Action

### Quick Action: `Approve (+30 days)`

- Prefills approval fields for that dependency.
- Auto-fills `Expires` with +30 days if empty.
- You still confirm by clicking `Add/Update Approval` in the approval form.

### Status messages near dependency list

You now see, in the same section:

- latest action result (`status message`)
- `Pip install guard` summary

This was moved here to avoid confusion with advanced findings.

## Manage Dependencies

You can now manage dependencies directly in UI without manual shell commands.

Fields:

- `Manager`: `pip` or `npm`
- `Action`: `Install`, `Update`, `Uninstall`
- `Package`: dependency name
- `Version`: required for manual install/update
- `Mode`:
  - `Manual (exact version)` -> you must provide exact version like `0.4.6`
  - `Auto (safe latest via manager)` -> UI resolves latest version and pins it

Safety behavior:

- Before install/update/uninstall, UI runs a pre-check scan at `CRITICAL`.
- After action, UI runs a post-check scan at `CRITICAL`.
- If critical blockers exist, action is blocked (or flagged after action).
- If trust signals are uncertain (for example very new package or missing local metadata), UI requires explicit user approval.

Examples:

- You run `Safe Update` on a package released yesterday:
  - UI warns that it is very new or not fully trusted yet
  - you can confirm from the Safe Update approval overlay (`Confirm update` / `Cancel`)
- You install a package with exact version but no local metadata cache:
  - UI may ask for explicit approval before proceeding

## Exceptions: Explain Scan Warnings/Errors

### Explain rule

- Enter a rule code, for example `FLOATING_VERSION`.
- Click `Explain Rule` to see a plain explanation.

## Exceptions: Baseline And Approvals

### Report path

- Usually: `security-artifacts/safedeps-report.json`.

### Baseline output path

- Usually: `.safedeps/vuln-baseline.json`.

### Create Baseline

- Generates suppression entries from the report.

### Approval Form (inside Section 5)

Use this when you want a controlled exception.

Fields:

- `Baseline file`: usually `.safedeps/vuln-baseline.json`
- `Manager`: `npm`, `pip`, `nuget`, `git`
- `Rule`: e.g. `FLOATING_VERSION`
- `Package` (optional): e.g. `lodash`
- `File` (optional): e.g. `package.json`
- `Expires (YYYY-MM-DD)`: required, e.g. `2026-12-31`

### Add/Update Approval

- Saves or updates the approval entry in baseline JSON.

## Policy Quick Editor

This section updates policy safely from UI (no manual JSON editing for common tasks).

### Add Registry To Allowlist

Fields:

- `Policy file (optional)`
- `Manager` (example: `npm`)
- `Registry URL to trust` (example: `https://registry.npmjs.org/`)

Button:

- `Add Registry To Allowlist`

Result:

- URL is added to `allowed_registries.<manager>` in policy file.

### Package denylist actions

Fields:

- `Policy action`: `Add deny package` or `Remove deny package`
- `Package name`
- `Policy file (optional)`

Button:

- `Apply Package Policy Action`

Result:

- Package is added/removed from `deny_packages`.

## Intelligence Settings

You can still edit advanced JSON here.

- `Local vulnerability feed JSON` -> `.safedeps/vuln-feed.json`
- `Local metadata cache JSON` -> `.safedeps/metadata-cache.json`

Buttons:

- `Save Intelligence Files`: validate and save
- `Create Starter Templates`: create default JSON templates

## Advanced Findings (collapsible)

This panel is for advanced workflows and manual exception preparation.

Each row shows severity, manager, rule, package, file, and message.

Action button:

- `Use For Approval` fills approval form from that finding.

## Page And Collapse Behavior

- Primary workflows are separated into sidebar pages instead of one long vertical document.
- Advanced panels inside a page remain collapsible where that is useful.
- Advanced findings table is collapsible inside `Dependencies`.

## Common Issues

### `{ "ok": false, "detail": "not_found" }`

- Open the exact URL printed by terminal output.
- If needed, set a custom port (`--port 5200`) and retry.

### Blank page with browser console extension errors

- Usually browser extension noise.
- Try incognito/private mode.

### Text or controls overflow their containers

- Long project paths, package names, dependency messages, and command output should wrap or scroll inside their panel.
- If overflow still appears, capture the page name and viewport size before reporting it.
