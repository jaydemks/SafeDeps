from __future__ import annotations

import json
import re
from pathlib import Path

from safedeps.models import Finding
from safedeps.scanners.base import Scanner, iter_files, path_is_excluded, severity_for_exception
from safedeps.scanners.metadata_signals import MetadataSignals
from safedeps.verifiers import verify_package

try:
    import yaml
except Exception:  # pragma: no cover - optional dependency
    yaml = None

BAD_NAME_HINTS = ["crypto", "stealer", "grabber", "token", "discord-token", "postinstall"]


class NpmScanner(Scanner):
    manager = "npm"
    manifests = ("package.json",)
    lockfiles = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
    supports_runtime_guard = False

    def scan(self, root: Path, policy):
        findings: list[Finding] = []
        components: list[dict] = []
        package_files: list[Path] = []
        signals = MetadataSignals.load(root)

        for pkgfile in iter_files(root, "package.json"):
            if path_is_excluded(root, pkgfile, policy):
                continue
            if "node_modules" in pkgfile.parts:
                continue
            package_files.append(pkgfile)
            try:
                data = json.loads(pkgfile.read_text(encoding="utf-8"))
            except Exception as e:
                findings.append(Finding("HIGH", "npm", "INVALID_MANIFEST", f"Cannot parse package.json: {e}", str(pkgfile.relative_to(root))))
                continue
            file_ref = str(pkgfile.relative_to(root))
            for section in ["dependencies", "devDependencies", "optionalDependencies"]:
                for name, ver in data.get(section, {}).items():
                    components.append({"type": "library", "manager": "npm", "name": name, "version": ver, "scope": section})
                    if policy.is_denied(name):
                        findings.append(Finding("CRITICAL", "npm", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                    self._append_supply_chain_signals(policy, findings, signals, "npm", name, file_ref)
                    if str(ver).startswith(("^", "~", "*")) or str(ver).lower() == "latest":
                        sev = severity_for_exception(policy, "npm", name, "FLOATING_VERSION")
                        findings.append(Finding(sev, "npm", "FLOATING_VERSION", f"Floating npm version for {name}: {ver}", file_ref, name, fix="Pin an exact version and commit package-lock.json."))
                    if any(h in name.lower() for h in BAD_NAME_HINTS):
                        findings.append(Finding("MEDIUM", "npm", "SUSPICIOUS_NAME", f"Suspicious package name pattern: {name}", file_ref, name, fix="Verify publisher, repo, age, and download history."))
            scripts = data.get("scripts", {})
            for key in ["preinstall", "install", "postinstall", "prepare"]:
                if key in scripts:
                    findings.append(Finding("HIGH", "npm", "INSTALL_SCRIPT", f"Install lifecycle script present: {key}", file_ref, fix="Review script before install; disable scripts in CI if possible."))

        self._scan_discovered_lockfiles(root, policy, findings, components, signals)

        if policy.data.get("require_lockfiles", True):
            for pkgfile in package_files:
                if not self._has_lockfile_for_manifest(pkgfile.parent, root):
                    findings.append(Finding("MEDIUM", "npm", "MISSING_LOCKFILE", f"Node project found but no lockfile detected for {pkgfile.parent.relative_to(root)}.", str(pkgfile.relative_to(root)), fix="Generate and commit package-lock.json, pnpm-lock.yaml, or yarn.lock in this package or a parent workspace."))

        npmrc = root / ".npmrc"
        if npmrc.exists():
            for line in npmrc.read_text(errors="ignore").splitlines():
                if line.strip().startswith("registry="):
                    url = line.split("=", 1)[1].strip()
                    if url not in policy.data["allowed_registries"].get("npm", []):
                        findings.append(Finding("CRITICAL", "npm", "UNTRUSTED_REGISTRY", f"NPM registry not in allowlist: {url}", ".npmrc", fix="Use approved registry or add a temporary exception."))
        return findings, components

    def _append_supply_chain_signals(self, policy, findings: list[Finding], signals: MetadataSignals, manager: str, name: str, file_ref: str):
        findings.extend(verify_package(policy, manager, name, file_ref, signals))

    def _scan_discovered_lockfiles(self, root: Path, policy, findings: list[Finding], components: list[dict], signals: MetadataSignals):
        seen: set[Path] = set()
        for lock in iter_files(root, "package-lock.json"):
            if path_is_excluded(root, lock, policy):
                continue
            if lock in seen:
                continue
            seen.add(lock)
            self._scan_package_lock(lock, root, policy, findings, components, signals)
        for lock in iter_files(root, "pnpm-lock.yaml"):
            if path_is_excluded(root, lock, policy):
                continue
            if lock in seen:
                continue
            seen.add(lock)
            self._scan_pnpm_lock(lock, root, policy, findings, components, signals)
        for lock in iter_files(root, "yarn.lock"):
            if path_is_excluded(root, lock, policy):
                continue
            if lock in seen:
                continue
            seen.add(lock)
            self._scan_yarn_lock(lock, root, policy, findings, components, signals)

    def _has_lockfile_for_manifest(self, start_dir: Path, root: Path) -> bool:
        current = start_dir
        while True:
            if any((current / name).exists() for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")):
                return True
            if current == root or current.parent == current or root not in current.parents:
                return False
            current = current.parent

    def _scan_package_lock(self, path: Path, root: Path, policy, findings: list[Finding], components: list[dict], signals: MetadataSignals):
        file_ref = str(path.relative_to(root))
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            findings.append(Finding("HIGH", "npm", "INVALID_PACKAGE_LOCK", f"Cannot parse package-lock.json: {e}", file_ref))
            return

        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for meta in packages.values():
                if not isinstance(meta, dict):
                    continue
                name = str(meta.get("name", "")).strip()
                version = str(meta.get("version", "")).strip()
                if not name:
                    continue
                components.append({"type": "library", "manager": "npm", "name": name, "version": version, "scope": "package-lock:packages"})
                if policy.is_denied(name):
                    findings.append(Finding("CRITICAL", "npm", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                self._append_supply_chain_signals(policy, findings, signals, "npm", name, file_ref)

        dependencies = data.get("dependencies", {})
        if isinstance(dependencies, dict):
            for name, meta in dependencies.items():
                if not isinstance(name, str) or not name.strip():
                    continue
                version = ""
                if isinstance(meta, dict):
                    version = str(meta.get("version", "")).strip()
                components.append({"type": "library", "manager": "npm", "name": name.strip(), "version": version, "scope": "package-lock:dependencies"})
                if policy.is_denied(name):
                    findings.append(Finding("CRITICAL", "npm", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                self._append_supply_chain_signals(policy, findings, signals, "npm", name, file_ref)

    def _scan_pnpm_lock(self, path: Path, root: Path, policy, findings: list[Finding], components: list[dict], signals: MetadataSignals):
        file_ref = str(path.relative_to(root))
        if yaml is None:
            findings.append(Finding("LOW", "npm", "PNPM_YAML_PARSER_MISSING", "pnpm-lock.yaml found but YAML parser not available; lockfile deep scan skipped.", file_ref, fix="Install PyYAML to enable pnpm lockfile parsing."))
            return
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as e:
            findings.append(Finding("HIGH", "npm", "INVALID_PNPM_LOCK", f"Cannot parse pnpm-lock.yaml: {e}", file_ref))
            return
        if not isinstance(data, dict):
            findings.append(Finding("HIGH", "npm", "INVALID_PNPM_LOCK", "pnpm-lock.yaml does not contain a valid mapping object.", file_ref))
            return

        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for key, meta in packages.items():
                name = self._extract_pnpm_name(key)
                if not name:
                    continue
                version = ""
                if isinstance(meta, dict):
                    version = str(meta.get("version", "")).strip()
                components.append({"type": "library", "manager": "npm", "name": name, "version": version, "scope": "pnpm-lock:packages"})
                if policy.is_denied(name):
                    findings.append(Finding("CRITICAL", "npm", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                self._append_supply_chain_signals(policy, findings, signals, "npm", name, file_ref)

    def _extract_pnpm_name(self, key: object) -> str:
        raw = str(key).strip()
        if not raw:
            return ""
        if raw.startswith("/"):
            raw = raw[1:]
        if "(" in raw:
            raw = raw.split("(", 1)[0]
        if raw.startswith("@"):
            at = raw.rfind("@")
            return raw[:at] if at > 0 else raw
        return raw.split("@", 1)[0]

    def _scan_yarn_lock(self, path: Path, root: Path, policy, findings: list[Finding], components: list[dict], signals: MetadataSignals):
        file_ref = str(path.relative_to(root))
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            if not stripped or line.startswith("#") or line.startswith(" "):
                i += 1
                continue
            if not stripped.endswith(":"):
                i += 1
                continue
            selectors = stripped[:-1]
            names = self._extract_yarn_names(selectors)
            version = ""
            j = i + 1
            while j < len(lines) and (lines[j].startswith("  ") or not lines[j].strip()):
                inner = lines[j].strip()
                if inner.startswith("version "):
                    m = re.match(r'version\s+"?([^"]+)"?', inner)
                    if m:
                        version = m.group(1)
                j += 1
            for name in names:
                components.append({"type": "library", "manager": "npm", "name": name, "version": version, "scope": "yarn-lock"})
                if policy.is_denied(name):
                    findings.append(Finding("CRITICAL", "npm", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                self._append_supply_chain_signals(policy, findings, signals, "npm", name, file_ref)
            i = j

    def _extract_yarn_names(self, selectors: str) -> list[str]:
        names: list[str] = []
        for raw_selector in selectors.split(","):
            selector = raw_selector.strip().strip('"').strip("'")
            if not selector:
                continue
            if selector.startswith("@"):
                at = selector.rfind("@")
                if at > 0:
                    names.append(selector[:at])
            else:
                names.append(selector.split("@", 1)[0])
        return [n for n in names if n]
