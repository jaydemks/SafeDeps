from __future__ import annotations
from dataclasses import dataclass, asdict
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

@dataclass
class ScanResult:
    ok: bool
    findings: list[Finding]
    sbom: dict[str, Any]

    def to_dict(self):
        return {"ok": self.ok, "findings": [asdict(f) for f in self.findings], "sbom": self.sbom}
