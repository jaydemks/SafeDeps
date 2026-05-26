from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from safedeps.models import Finding
from safedeps.scanners.base import Scanner, iter_files, path_is_excluded, severity_for_exception
from safedeps.scanners.metadata_signals import MetadataSignals, age_finding, churn_finding, maintainer_change_finding
from safedeps.scanners.typosquat import typosquat_finding

PINNED_PIP = re.compile(r"^[A-Za-z0-9_.-]+(\[[^\]]+\])?==[^=<>!~]+")


class PipScanner(Scanner):
    manager = "pip"

    def scan(self, root: Path, policy):
        findings: list[Finding] = []
        components: list[dict] = []
        has_python_manifest = False
        signals = MetadataSignals.load(root)

        for req in iter_files(root, "requirements*.txt"):
            if path_is_excluded(root, req, policy):
                continue
            if any(part.startswith(".") and part not in (".safedeps",) for part in req.relative_to(root).parts):
                continue
            has_python_manifest = True
            for line in req.read_text(errors="ignore").splitlines():
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                if raw.startswith(("--index-url", "--extra-index-url", "-i")):
                    url = raw.split()[-1]
                    allowed = policy.data["allowed_registries"].get("pip", [])
                    if url not in allowed:
                        findings.append(
                            Finding(
                                "CRITICAL",
                                "pip",
                                "UNTRUSTED_REGISTRY",
                                f"Pip index not in allowlist: {url}",
                                str(req.relative_to(root)),
                                fix="Use an approved index or add a temporary exception.",
                            )
                        )
                    continue
                name = re.split(r"[=<>!~\[]", raw)[0].strip()
                if not name:
                    continue
                file_ref = str(req.relative_to(root))
                components.append({"type": "library", "manager": "pip", "name": name, "version": raw.replace(name, "").strip()})
                if policy.is_denied(name):
                    findings.append(Finding("CRITICAL", "pip", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                self._append_supply_chain_signals(policy, findings, signals, "pip", name, file_ref)
                if not policy.data.get("allow_unpinned", False) and not PINNED_PIP.match(raw) and not raw.startswith(("git+", "http://", "https://")):
                    sev = severity_for_exception(policy, "pip", name, "UNPINNED_VERSION")
                    findings.append(Finding(sev, "pip", "UNPINNED_VERSION", f"Unpinned pip dependency: {raw}", file_ref, name, fix="Pin with == and record hashes where possible."))
                if raw.startswith(("git+", "http://")):
                    findings.append(Finding("HIGH", "pip", "DIRECT_URL", f"Direct URL dependency requires explicit review: {raw}", file_ref, name, fix="Prefer registry package, commit SHA, and hash verification."))

        for pyproject in iter_files(root, "pyproject.toml"):
            if path_is_excluded(root, pyproject, policy):
                continue
            if any(part.startswith(".") and part not in (".safedeps",) for part in pyproject.relative_to(root).parts):
                continue
            has_python_manifest = True
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            except Exception as e:
                findings.append(Finding("HIGH", "pip", "INVALID_PYPROJECT", f"Cannot parse pyproject.toml: {e}", str(pyproject.relative_to(root))))
                continue
            project = data.get("project", {})
            for raw in project.get("dependencies", []):
                self._check_dep_string(raw, str(pyproject.relative_to(root)), policy, findings, components, "dependencies", signals)
            optional = project.get("optional-dependencies", {})
            for group, deps in optional.items():
                for raw in deps:
                    self._check_dep_string(raw, str(pyproject.relative_to(root)), policy, findings, components, f"optional:{group}", signals)

        poetry_lock = root / "poetry.lock"
        if poetry_lock.exists():
            has_python_manifest = True
            self._scan_python_lock_toml(poetry_lock, "poetry", policy, findings, components, signals)

        uv_lock = root / "uv.lock"
        if uv_lock.exists():
            has_python_manifest = True
            self._scan_python_lock_toml(uv_lock, "uv", policy, findings, components, signals)

        pipfile_lock = root / "Pipfile.lock"
        if pipfile_lock.exists():
            has_python_manifest = True
            self._scan_pipfile_lock(pipfile_lock, policy, findings, components, signals)

        if policy.data.get("require_lockfiles", True) and has_python_manifest and not any((root / p).exists() for p in ["requirements.lock", "uv.lock", "poetry.lock", "Pipfile.lock"]):
            findings.append(Finding("MEDIUM", "pip", "MISSING_LOCKFILE", "Python dependencies found but no lockfile detected.", fix="Generate poetry.lock, uv.lock, Pipfile.lock, or requirements.lock."))
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

    def _check_dep_string(self, raw: str, file_ref: str, policy, findings: list[Finding], components: list[dict], scope: str, signals: MetadataSignals):
        dep = str(raw).strip()
        if not dep:
            return
        name = re.split(r"[<>=!~;\[\s]", dep, 1)[0].strip()
        if not name:
            return
        components.append({"type": "library", "manager": "pip", "name": name, "version": dep.replace(name, "", 1).strip(), "scope": scope})
        if policy.is_denied(name):
            findings.append(Finding("CRITICAL", "pip", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
        self._append_supply_chain_signals(policy, findings, signals, "pip", name, file_ref)
        pinned_exact = "==" in dep and not dep.startswith(("git+", "http://", "https://"))
        if not policy.data.get("allow_unpinned", False) and not pinned_exact and not dep.startswith(("git+", "http://", "https://")):
            sev = severity_for_exception(policy, "pip", name, "UNPINNED_VERSION")
            findings.append(Finding(sev, "pip", "UNPINNED_VERSION", f"Unpinned pip dependency: {dep}", file_ref, name, fix="Pin with == and record hashes where possible."))

    def _scan_python_lock_toml(self, path: Path, manager: str, policy, findings: list[Finding], components: list[dict], signals: MetadataSignals):
        file_ref = str(path.name)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            rule = "INVALID_POETRY_LOCK" if manager == "poetry" else "INVALID_UV_LOCK"
            findings.append(Finding("HIGH", "pip", rule, f"Cannot parse {path.name}: {e}", file_ref))
            return
        for item in data.get("package", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            version = str(item.get("version", "")).strip()
            if not name:
                continue
            components.append({"type": "library", "manager": "pip", "name": name, "version": version, "scope": f"{manager}-lock"})
            if policy.is_denied(name):
                findings.append(Finding("CRITICAL", "pip", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
            self._append_supply_chain_signals(policy, findings, signals, "pip", name, file_ref)

    def _scan_pipfile_lock(self, path: Path, policy, findings: list[Finding], components: list[dict], signals: MetadataSignals):
        file_ref = str(path.name)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            findings.append(Finding("HIGH", "pip", "INVALID_PIPFILE_LOCK", f"Cannot parse Pipfile.lock: {e}", file_ref))
            return
        for section in ("default", "develop"):
            section_data = data.get(section, {})
            if not isinstance(section_data, dict):
                continue
            for name, meta in section_data.items():
                if not isinstance(name, str) or not name.strip():
                    continue
                version = ""
                if isinstance(meta, dict):
                    version = str(meta.get("version", "")).strip()
                components.append({"type": "library", "manager": "pip", "name": name.strip(), "version": version, "scope": f"pipfile-lock:{section}"})
                if policy.is_denied(name):
                    findings.append(Finding("CRITICAL", "pip", "DENYLIST", f"Denied package: {name}", file_ref, name, fix="Remove or replace this dependency."))
                self._append_supply_chain_signals(policy, findings, signals, "pip", name, file_ref)
