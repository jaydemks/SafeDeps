from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from safedeps.models import Finding
from safedeps.scanners.base import Scanner
from safedeps.scanners.metadata_signals import MetadataSignals, age_finding, churn_finding, maintainer_change_finding
from safedeps.scanners.typosquat import typosquat_finding


class NugetScanner(Scanner):
    manager = "nuget"

    def scan(self, root: Path, policy):
        findings: list[Finding] = []
        components: list[dict] = []
        has_nuget_manifest = False
        signals = MetadataSignals.load(root)

        for csproj in root.rglob("*.csproj"):
            has_nuget_manifest = True
            try:
                tree = ET.parse(csproj)
            except Exception as e:
                findings.append(Finding("HIGH", "nuget", "INVALID_CSPROJ", f"Cannot parse csproj: {e}", str(csproj.relative_to(root))))
                continue
            file_ref = str(csproj.relative_to(root))
            for pr in tree.findall(".//PackageReference"):
                name = pr.attrib.get("Include") or pr.attrib.get("Update") or ""
                ver = pr.attrib.get("Version") or (pr.findtext("Version") or "")
                if not name:
                    continue
                components.append({"type": "library", "manager": "nuget", "name": name, "version": ver})
                if policy.is_denied(name):
                    findings.append(Finding("CRITICAL", "nuget", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                self._append_supply_chain_signals(policy, findings, signals, "nuget", name, file_ref)
                if not ver or "*" in ver or (not ver.startswith("[") and "," in ver):
                    findings.append(Finding("HIGH", "nuget", "FLOATING_VERSION", f"Floating or range NuGet version for {name}: {ver or '(none)'}", file_ref, name, fix="Use exact PackageReference versions and packages.lock.json."))

        props = root / "Directory.Packages.props"
        if props.exists():
            has_nuget_manifest = True
            self._scan_directory_packages_props(props, policy, findings, components, signals)

        packages_config_files = list(root.rglob("packages.config"))
        if packages_config_files:
            has_nuget_manifest = True
        for pconfig in packages_config_files:
            self._scan_packages_config(pconfig, root, policy, findings, components, signals)

        lockfiles = list(root.rglob("packages.lock.json"))
        for lockfile in lockfiles:
            self._scan_packages_lock(lockfile, root, policy, findings, components, signals)

        for cfg in [root / "NuGet.Config", root / "nuget.config"]:
            if cfg.exists():
                txt = cfg.read_text(errors="ignore")
                urls = re.findall(r'value=["\']([^"\']+)["\']', txt)
                for url in urls:
                    if url.startswith("http") and url not in policy.data["allowed_registries"].get("nuget", []):
                        findings.append(Finding("CRITICAL", "nuget", "UNTRUSTED_REGISTRY", f"NuGet source not in allowlist: {url}", cfg.name, fix="Use approved source or add a temporary exception."))

        if policy.data.get("require_lockfiles", True) and has_nuget_manifest and not any(root.rglob("packages.lock.json")):
            findings.append(Finding("MEDIUM", "nuget", "MISSING_LOCKFILE", ".NET project found but no packages.lock.json detected.", fix="Enable RestorePackagesWithLockFile and commit packages.lock.json."))

        return findings, components

    def _append_supply_chain_signals(self, policy, findings: list[Finding], signals: MetadataSignals, manager: str, name: str, file_ref: str):
        typo = typosquat_finding(policy, manager, name, file_ref)
        if typo:
            findings.append(typo)
        age = age_finding(policy, manager, name, file_ref, signals)
        if age:
            findings.append(age)
        churn = churn_finding(policy, manager, name, file_ref, signals)
        if churn:
            findings.append(churn)
        maint = maintainer_change_finding(policy, manager, name, file_ref, signals)
        if maint:
            findings.append(maint)

    def _scan_directory_packages_props(self, path: Path, policy, findings: list[Finding], components: list[dict], signals: MetadataSignals):
        try:
            tree = ET.parse(path)
        except Exception as e:
            findings.append(Finding("HIGH", "nuget", "INVALID_DIRECTORY_PACKAGES_PROPS", f"Cannot parse Directory.Packages.props: {e}", path.name))
            return

        for pv in tree.findall(".//PackageVersion"):
            name = pv.attrib.get("Include") or ""
            ver = pv.attrib.get("Version") or ""
            if not name:
                continue
            components.append({"type": "library", "manager": "nuget", "name": name, "version": ver, "scope": "Directory.Packages.props"})
            if policy.is_denied(name):
                findings.append(Finding("CRITICAL", "nuget", "DENYLIST", f"Denied package: {name}", path.name, name, fix="Remove or replace this dependency."))
            self._append_supply_chain_signals(policy, findings, signals, "nuget", name, path.name)
            if not ver or "*" in ver or (not ver.startswith("[") and "," in ver):
                findings.append(Finding("HIGH", "nuget", "FLOATING_VERSION", f"Floating or range NuGet version for {name}: {ver or '(none)'}", path.name, name, fix="Use exact PackageVersion values and lockfiles."))

    def _scan_packages_config(self, path: Path, root: Path, policy, findings: list[Finding], components: list[dict], signals: MetadataSignals):
        try:
            tree = ET.parse(path)
        except Exception as e:
            findings.append(Finding("HIGH", "nuget", "INVALID_PACKAGES_CONFIG", f"Cannot parse packages.config: {e}", str(path.relative_to(root))))
            return

        file_ref = str(path.relative_to(root))
        for pkg in tree.findall(".//package"):
            name = pkg.attrib.get("id") or ""
            ver = pkg.attrib.get("version") or ""
            if not name:
                continue
            components.append({"type": "library", "manager": "nuget", "name": name, "version": ver, "scope": "packages.config"})
            if policy.is_denied(name):
                findings.append(Finding("CRITICAL", "nuget", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
            self._append_supply_chain_signals(policy, findings, signals, "nuget", name, file_ref)
            if not ver or "*" in ver or (not ver.startswith("[") and "," in ver):
                findings.append(Finding("HIGH", "nuget", "FLOATING_VERSION", f"Floating or range NuGet version for {name}: {ver or '(none)'}", file_ref, name, fix="Use exact package versions and lockfiles."))

    def _scan_packages_lock(self, path: Path, root: Path, policy, findings: list[Finding], components: list[dict], signals: MetadataSignals):
        file_ref = str(path.relative_to(root))
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            findings.append(Finding("HIGH", "nuget", "INVALID_PACKAGES_LOCK", f"Cannot parse packages.lock.json: {e}", file_ref))
            return

        deps_root = data.get("dependencies", {})
        if not isinstance(deps_root, dict):
            findings.append(Finding("HIGH", "nuget", "INVALID_PACKAGES_LOCK", "packages.lock.json missing valid 'dependencies' object.", file_ref))
            return

        for tfm, packages in deps_root.items():
            if not isinstance(packages, dict):
                continue
            for name, meta in packages.items():
                if not isinstance(name, str) or not name.strip():
                    continue
                resolved = ""
                requested = ""
                if isinstance(meta, dict):
                    resolved = str(meta.get("resolved", "")).strip()
                    requested = str(meta.get("requested", "")).strip()
                version = resolved or requested
                components.append({"type": "library", "manager": "nuget", "name": name.strip(), "version": version, "scope": f"packages.lock.json:{tfm}"})
                if policy.is_denied(name):
                    findings.append(Finding("CRITICAL", "nuget", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                self._append_supply_chain_signals(policy, findings, signals, "nuget", name, file_ref)
