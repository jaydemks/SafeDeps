from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field
from pathlib import Path

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
  "enable_repository_link_checks": False,
  "enable_download_anomaly_checks": False,
  "min_downloads_30d": 25,
  "enable_vulnerability_baseline": True,
  "vulnerability_baseline_file": ".safedeps/vuln-baseline.json",
  "advisory_severity_threshold": "LOW",
  "metadata_risk_severity": "MEDIUM",
  "exclude_paths": [
    "examples/"
  ]
}


class PolicyValidationError(ValueError):
    def __init__(self, path: Path | None, issues: list[str]):
        self.path = path
        self.issues = issues
        location = f"{path}: " if path else ""
        super().__init__(location + "; ".join(issues))


@dataclass
class Policy:
    data: dict = field(default_factory=lambda: dict(DEFAULT_POLICY))
    path: Path | None = None

    @classmethod
    def load(cls, project: Path, explicit: str | None = None) -> Policy:
        candidates = []
        if explicit:
            candidates.append(Path(explicit))
        candidates += [project / ".safedeps" / "policy.json", project / "safedeps.policy.json"]
        for p in candidates:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                issues = validate_policy_schema_v1(data)
                if issues:
                    raise PolicyValidationError(p, issues)
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


def validate_policy_schema_v1(policy: object) -> list[str]:
    issues: list[str] = []
    if not isinstance(policy, dict):
        return ["policy.json must be a JSON object."]

    schema = policy.get("schema")
    if schema is not None and schema != "safedeps.policy.v1":
        issues.append("policy.schema must be 'safedeps.policy.v1' when present.")

    allowed = policy.get("allowed_registries")
    if allowed is not None:
        if not isinstance(allowed, dict):
            issues.append("policy.allowed_registries must be an object when present.")
        else:
            for manager, urls in allowed.items():
                if not isinstance(manager, str) or not manager.strip():
                    issues.append("policy.allowed_registries keys must be non-empty strings.")
                    continue
                if not isinstance(urls, list):
                    issues.append(f"policy.allowed_registries.{manager} must be a list of registry URLs.")
                    continue
                for index, url in enumerate(urls):
                    if not isinstance(url, str) or not url.strip():
                        issues.append(
                            f"policy.allowed_registries.{manager}[{index}] must be a non-empty string."
                        )

    deny = policy.get("deny_packages")
    if deny is not None:
        if not isinstance(deny, list):
            issues.append("policy.deny_packages must be a list when present.")
        else:
            for index, package in enumerate(deny):
                if not isinstance(package, str) or not package.strip():
                    issues.append(f"policy.deny_packages[{index}] must be a non-empty string.")

    _validate_bool(policy, "allow_unpinned", issues)
    _validate_bool(policy, "require_lockfiles", issues)
    _validate_bool(policy, "enable_package_age_checks", issues)
    _validate_bool(policy, "enable_publisher_churn_checks", issues)
    _validate_bool(policy, "enable_maintainer_change_checks", issues)
    _validate_bool(policy, "enable_repository_link_checks", issues)
    _validate_bool(policy, "enable_download_anomaly_checks", issues)

    _validate_non_negative_int(policy, "min_package_age_days", issues)
    _validate_non_negative_int(policy, "max_publisher_changes_90d", issues)
    _validate_non_negative_int(policy, "max_maintainer_changes_180d", issues)
    _validate_non_negative_int(policy, "min_downloads_30d", issues)

    _validate_severity(policy, "advisory_severity_threshold", issues)
    _validate_severity(policy, "metadata_risk_severity", issues)

    exceptions = policy.get("exceptions")
    if exceptions is not None and not isinstance(exceptions, list):
        issues.append("policy.exceptions must be a list when present.")

    return issues


def _validate_bool(policy: dict, key: str, issues: list[str]) -> None:
    value = policy.get(key)
    if value is not None and not isinstance(value, bool):
        issues.append(f"policy.{key} must be true or false when present.")


def _validate_non_negative_int(policy: dict, key: str, issues: list[str]) -> None:
    value = policy.get(key)
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        issues.append(f"policy.{key} must be a non-negative integer when present.")


def _validate_severity(policy: dict, key: str, issues: list[str]) -> None:
    value = policy.get(key)
    if value is None:
        return
    allowed = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if not isinstance(value, str) or value.upper() not in allowed:
        issues.append(
            f"policy.{key} must be one of INFO, LOW, MEDIUM, HIGH, or CRITICAL when present."
        )
