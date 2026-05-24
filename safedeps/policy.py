from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import json, datetime

DEFAULT_POLICY = {
  "schema": "safedeps.policy.v1",
  "allowed_registries": {
    "npm": ["https://registry.npmjs.org/"],
    "pip": ["https://pypi.org/simple", "https://pypi.org/simple/"],
    "nuget": ["https://api.nuget.org/v3/index.json"]
  },
  "deny_packages": [],
  "allow_unpinned": False,
  "require_lockfiles": True,
  "require_expiring_exceptions": True,
  "exceptions": [],
  "enable_typosquat_detection": True,
  "protected_packages": ["requests", "numpy", "pandas", "lodash", "react", "Newtonsoft.Json"],
  "enable_package_age_checks": False,
  "min_package_age_days": 14,
  "enable_publisher_churn_checks": False,
  "max_publisher_changes_90d": 1,
  "enable_maintainer_change_checks": False,
  "max_maintainer_changes_180d": 1,
  "enable_vulnerability_baseline": True,
  "vulnerability_baseline_file": ".safedeps/vuln-baseline.json"
}

@dataclass
class Policy:
    data: dict = field(default_factory=lambda: dict(DEFAULT_POLICY))
    path: Path | None = None

    @classmethod
    def load(cls, project: Path, explicit: str | None = None) -> "Policy":
        candidates = []
        if explicit:
            candidates.append(Path(explicit))
        candidates += [project / ".safedeps" / "policy.json", project / "safedeps.policy.json"]
        for p in candidates:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                merged = json.loads(json.dumps(DEFAULT_POLICY))
                deep_update(merged, data)
                return cls(merged, p)
        return cls(json.loads(json.dumps(DEFAULT_POLICY)), None)

    def is_denied(self, name: str) -> bool:
        low = name.lower()
        return any(low == str(x).lower() for x in self.data.get("deny_packages", []))

    def has_exception(self, manager: str, package: str, rule: str) -> bool:
        today = datetime.date.today()
        for ex in self.data.get("exceptions", []):
            if ex.get("manager") not in (manager, "*"): continue
            if ex.get("package") not in (package, "*"): continue
            if ex.get("rule") not in (rule, "*"): continue
            until = ex.get("expires")
            if self.data.get("require_expiring_exceptions", True) and not until:
                continue
            if until and datetime.date.fromisoformat(until) < today:
                continue
            return True
        return False

def deep_update(a: dict, b: dict) -> dict:
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(a.get(k), dict):
            deep_update(a[k], v)
        else:
            a[k] = v
    return a
