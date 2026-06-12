# SafeDeps UI - Practical User Guide

This guide explains the current UI workflow in plain language.

## Open The UI

Recommended command from the project root:

```bash
safedeps ui .
```

Behavior:

- `safedeps ui .` opens the UI on the current project root.
- `safedeps ui` opens the current directory when it looks like a project; otherwise it creates/uses `~/.safedeps/workspace`.
- Default start port is `5200` and SafeDeps auto-tries next local ports if one is blocked.
- On Windows you can create a desktop launcher with `safedeps ui-shortcut`.

## Light/Dark Theme

- Click `Theme` in the top-right corner.
- The UI remembers your choice in the browser.

## Auto Guard + Scope (PowerShell)

At the top of the UI you now have:

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

The header cards show:

- setup status
- auto-guard status
- current shell guard status

## Recommended Workflow

1. Click `Setup Project Guard` (first time per project).
2. In `Run Scan`, keep `Project path` as `.` and `Fail on` as `HIGH`.
3. Click `Run Scan`.
4. Review `Dependency View And Quick Actions`.
5. Use quick actions or policy editor.
6. Re-run scan to confirm result.

Note:

- By default, repository sample fixtures under `examples/` are excluded from scans via policy (`exclude_paths`) to keep real-project checks cleaner.

## Section 1: Run Scan

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

## Section 2: Dependency View And Quick Actions

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

## Section 3: Manage Dependencies (Guided)

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

## Section 4: Explain Scan Warnings/Errors (Advanced)

### Explain rule

- Enter a rule code, for example `FLOATING_VERSION`.
- Click `Explain Rule` to see a plain explanation.

## Section 5: Baseline And Exceptions (Advanced)

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

## Section 6: Policy Quick Editor (Advanced)

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

## Section 7: Intelligence Settings (Advanced)

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

## Section Collapse Behavior

- Sections `1`, `2`, and `3` are primary and always visible.
- Advanced sections (`4`, `5`, `6`, `7`) are collapsible and start closed by default.
- Advanced findings table is also collapsible.

## Common Issues

### `{ "ok": false, "detail": "not_found" }`

- Open the exact URL printed by terminal output.
- If needed, set a custom port (`--port 5200`) and retry.

### Blank page with browser console extension errors

- Usually browser extension noise.
- Try incognito/private mode.

### Text or controls overflow their containers

- This is a known visual issue in the current UI.
- It can happen with long project paths, package names, dependency messages, or narrow browser widths.
- The planned UI restyle will replace the current ad hoc layout with a responsive layout system and explicit overflow handling.
