from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from safedeps.models import Finding
from safedeps.scanners.base import Scanner, iter_files, path_is_excluded
from safedeps.scanners.metadata_signals import MetadataSignals
from safedeps.verifiers import verify_package


def _is_floating_or_range_version(version: str) -> bool:
    ver = str(version or "").strip()
    if not ver:
        return True
    if "*" in ver:
        return True
    if "," in ver:
        return True
    return ver.startswith(("[", "(")) or ver.endswith(("]", ")"))


class NugetScanner(Scanner):
    manager = "nuget"
    manifests = ("*.csproj", "Directory.Packages.props", "packages.config", "NuGet.Config", "nuget.config")
    lockfiles = ("packages.lock.json",)
    supports_runtime_guard = False

    def scan(self, root: Path, policy):
        findings: list[Finding] = []
        components: list[dict] = []
        has_nuget_manifest = False
        signals = MetadataSignals.load(root)

        for csproj in iter_files(root, "*.csproj"):
            if path_is_excluded(root, csproj, policy):
                continue
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
                if _is_floating_or_range_version(ver):
                    findings.append(Finding("HIGH", "nuget", "FLOATING_VERSION", f"Floating or range NuGet version for {name}: {ver or '(none)'}", file_ref, name, fix="Use exact PackageReference versions and packages.lock.json."))

        props = root / "Directory.Packages.props"
        if props.exists():
            has_nuget_manifest = True
            self._scan_directory_packages_props(props, policy, findings, components, signals)

        packages_config_files = list(iter_files(root, "packages.config"))
        if packages_config_files:
            has_nuget_manifest = True
        for pconfig in packages_config_files:
            if path_is_excluded(root, pconfig, policy):
                continue
            self._scan_packages_config(pconfig, root, policy, findings, components, signals)

        lockfiles = list(iter_files(root, "packages.lock.json"))
        for lockfile in lockfiles:
            if path_is_excluded(root, lockfile, policy):
                continue
            self._scan_packages_lock(lockfile, root, policy, findings, components, signals)

        config_files: list[Path] = []
        for cfg in [root / "NuGet.Config", root / "nuget.config"]:
            if not cfg.exists():
                continue
            if any(cfg.samefile(existing) for existing in config_files):
                continue
            config_files.append(cfg)
        for cfg in config_files:
            self._scan_nuget_config(cfg, policy, findings)

        if policy.data.get("require_lockfiles", True) and has_nuget_manifest and not any(iter_files(root, "packages.lock.json")):
            findings.append(Finding("MEDIUM", "nuget", "MISSING_LOCKFILE", ".NET project found but no packages.lock.json detected.", fix="Enable RestorePackagesWithLockFile and commit packages.lock.json."))

        return findings, components

    def _append_supply_chain_signals(self, policy, findings: list[Finding], signals: MetadataSignals, manager: str, name: str, file_ref: str):
        findings.extend(verify_package(policy, manager, name, file_ref, signals))

    def _scan_nuget_config(self, path: Path, policy, findings: list[Finding]):
        try:
            tree = ET.parse(path)
        except Exception as e:
            findings.append(Finding("HIGH", "nuget", "INVALID_NUGET_CONFIG", f"Cannot parse NuGet.Config: {e}", path.name))
            return

        source_keys: set[str] = set()
        allowed_sources = set(policy.data["allowed_registries"].get("nuget", []))
        for source in tree.findall(".//packageSources/add"):
            key = str(source.attrib.get("key") or "").strip()
            url = str(source.attrib.get("value") or "").strip()
            if key:
                source_keys.add(key)
            if url.startswith("http") and url not in allowed_sources:
                findings.append(Finding("CRITICAL", "nuget", "UNTRUSTED_REGISTRY", f"NuGet source not in allowlist: {url}", path.name, fix="Use approved source or add a temporary exception."))

        for mapped_source in tree.findall(".//packageSourceMapping/packageSource"):
            key = str(mapped_source.attrib.get("key") or "").strip()
            patterns = [
                str(pattern.attrib.get("pattern") or "").strip()
                for pattern in mapped_source.findall("package")
            ]
            if not key or key not in source_keys:
                findings.append(Finding("HIGH", "nuget", "INVALID_SOURCE_MAPPING", f"NuGet source mapping references unknown source: {key or '(missing)'}", path.name, fix="Map packages only to configured packageSources."))
            if not any(patterns):
                findings.append(Finding("HIGH", "nuget", "INVALID_SOURCE_MAPPING", f"NuGet source mapping for {key or '(missing)'} has no package patterns.", path.name, fix="Add at least one package pattern for each mapped source."))

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
            if _is_floating_or_range_version(ver):
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
            if _is_floating_or_range_version(ver):
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
                    dependency_type = str(meta.get("type", "")).strip()
                else:
                    dependency_type = ""
                version = resolved or requested
                scope = f"packages.lock.json:{tfm}"
                if dependency_type:
                    scope = f"{scope}:{dependency_type}"
                components.append({"type": "library", "manager": "nuget", "name": name.strip(), "version": version, "scope": scope})
                if policy.is_denied(name):
                    findings.append(Finding("CRITICAL", "nuget", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                self._append_supply_chain_signals(policy, findings, signals, "nuget", name, file_ref)
