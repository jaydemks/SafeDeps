from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Finding:
    severity: str
    manager: str
    rule: str
    message: str
    file: str = ""
    package: str = ""
    fix: str = ""


@dataclass(frozen=True)
class PackageTarget:
    manager: str
    name: str
    version: str = ""
    file: str = ""
    scope: str = ""

    def to_component(self) -> dict[str, str]:
        component = {"type": "library", "manager": self.manager, "name": self.name, "version": self.version}
        if self.scope:
            component["scope"] = self.scope
        if self.file:
            component["file"] = self.file
        return component


@dataclass
class ScanResult:
    ok: bool
    findings: list[Finding]
    sbom: dict[str, Any]

    def to_dict(self):
        return {"ok": self.ok, "findings": [asdict(f) for f in self.findings], "sbom": self.sbom}
