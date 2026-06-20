from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping


def build_parser(
    *,
    version: str,
    severity_choices,
    handlers: Mapping[str, Callable],
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safedeps",
        description="Dependency policy gate for safer installs and updates.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {version}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_version = sub.add_parser("version", help="Print SafeDeps version")
    p_version.set_defaults(func=handlers["version"])

    p_help = sub.add_parser("help", help="Show quick usage commands for terminal/cmd/powershell")
    p_help.set_defaults(func=handlers["help"])

    p_init = sub.add_parser("init", help="Create .safedeps/policy.json")
    p_init.add_argument("path", nargs="?", default=".")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=handlers["init"])

    p_scan = sub.add_parser("scan", help="Scan a project before install/update")
    p_scan.add_argument("path", nargs="?", default=".")
    p_scan.add_argument("--policy")
    p_scan.add_argument("--out", default="security-artifacts")
    p_scan.add_argument("--sarif", default="", help="Optional SARIF output path (relative to scan root).")
    p_scan.add_argument("--cyclonedx", default="", help="Optional CycloneDX JSON output path (relative to scan root).")
    p_scan.add_argument("--spdx", default="", help="Optional SPDX JSON output path (relative to scan root).")
    p_scan.add_argument("--html", default="", help="Optional HTML output path (relative to scan root).")
    p_scan.add_argument("--fail-on", choices=list(severity_choices), default="HIGH")
    p_scan.add_argument(
        "--online-audit",
        action="store_true",
        help="Run ecosystem audit commands when available. Requires network/tooling.",
    )
    p_scan.set_defaults(func=handlers["scan"])

    p_doctor = sub.add_parser("doctor", help="Validate local SafeDeps setup and metadata cache health")
    p_doctor.add_argument("path", nargs="?", default=".")
    p_doctor.set_defaults(func=handlers["doctor"])

    p_explain = sub.add_parser("explain", help="Explain a finding rule and remediation intent")
    p_explain.add_argument("rule", help="Rule identifier (example: FLOATING_VERSION)")
    p_explain.set_defaults(func=handlers["explain"])

    p_baseline = sub.add_parser("baseline", help="Create baseline suppression file from scan report")
    p_baseline.add_argument("path", nargs="?", default=".")
    p_baseline.add_argument("--report", default="security-artifacts/safedeps-report.json")
    p_baseline.add_argument("--output", default=".safedeps/vuln-baseline.json")
    p_baseline.set_defaults(func=handlers["baseline"])

    p_approve = sub.add_parser("approve", help="Add expiring suppression entry to baseline file")
    p_approve.add_argument("path", nargs="?", default=".")
    p_approve.add_argument("--manager", required=True)
    p_approve.add_argument("--rule", required=True)
    p_approve.add_argument("--package", default="")
    p_approve.add_argument("--file", default="")
    p_approve.add_argument("--expires", required=True, help="Expiration date (YYYY-MM-DD)")
    p_approve.add_argument("--baseline", default=".safedeps/vuln-baseline.json")
    p_approve.set_defaults(func=handlers["approve"])

    p_ui = sub.add_parser("ui", help="Run local web UI for visual scans")
    p_ui.add_argument("path", nargs="?", default="")
    p_ui.add_argument("--host", default="127.0.0.1")
    p_ui.add_argument("--port", type=int, default=5200)
    p_ui.add_argument("--fail-on", choices=list(severity_choices), default="HIGH")
    p_ui.add_argument(
        "--install-scope",
        choices=("auto", "project", "system"),
        default="auto",
        help="Override detected SafeDeps install scope for UI testing.",
    )
    p_ui.add_argument("--open-browser", action="store_true", default=True)
    p_ui.add_argument("--no-open-browser", dest="open_browser", action="store_false")
    p_ui.set_defaults(func=handlers["ui"])

    p_ui_shortcut = sub.add_parser(
        "ui-shortcut",
        help="Create Windows desktop .bat launcher for SafeDeps UI",
    )
    p_ui_shortcut.set_defaults(func=handlers["ui-shortcut"])

    p_setup = sub.add_parser("setup", help="One-time project setup for guarded pip install")
    p_setup.add_argument("path", nargs="?", default=".")
    p_setup.add_argument("--fail-on", choices=list(severity_choices), default="HIGH")
    p_setup.add_argument("--force", action="store_true")
    p_setup.add_argument(
        "--install-scope",
        choices=("auto", "project", "system"),
        default="auto",
        help="Override detected SafeDeps install scope for guard setup.",
    )
    p_setup.add_argument(
        "--protection-scope",
        choices=("auto", "project", "global"),
        default="auto",
        help="Set the guard protection scope during setup.",
    )
    p_setup.set_defaults(func=handlers["setup"])

    p_guard_cleanup = sub.add_parser("guard-cleanup", help=argparse.SUPPRESS)
    p_guard_cleanup.add_argument("path", nargs="?", default=".")
    p_guard_cleanup.add_argument("--remove-project-artifacts", action="store_true")
    p_guard_cleanup.set_defaults(func=handlers["guard-cleanup"])
    return parser
