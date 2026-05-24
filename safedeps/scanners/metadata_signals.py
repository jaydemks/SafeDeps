from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from safedeps.models import Finding


class MetadataSignals:
    def __init__(self, data: dict):
        self.data = data

    @classmethod
    def load(cls, root: Path):
        cache = root / ".safedeps" / "metadata-cache.json"
        if not cache.exists():
            return cls({})
        try:
            return cls(json.loads(cache.read_text(encoding="utf-8")))
        except Exception:
            return cls({})

    def get(self, manager: str, package: str) -> dict:
        mgr = self.data.get(manager, {})
        if not isinstance(mgr, dict):
            return {}
        val = mgr.get(package, {})
        return val if isinstance(val, dict) else {}


def age_finding(policy, manager: str, package: str, file_ref: str, signals: MetadataSignals):
    if not policy.data.get("enable_package_age_checks", False):
        return None
    min_age_days = int(policy.data.get("min_package_age_days", 14))
    if min_age_days <= 0:
        return None
    meta = signals.get(manager, package)
    published = str(meta.get("published", "")).strip()
    if not published:
        return None
    try:
        published_date = dt.date.fromisoformat(published)
    except ValueError:
        return None
    age_days = (dt.date.today() - published_date).days
    if age_days < min_age_days:
        return Finding(
            "MEDIUM",
            manager,
            "PACKAGE_TOO_NEW",
            f"Package '{package}' is only {age_days} days old (< {min_age_days}).",
            file_ref,
            package,
            fix="Delay adoption or require elevated review for very new packages.",
        )
    return None


def churn_finding(policy, manager: str, package: str, file_ref: str, signals: MetadataSignals):
    if not policy.data.get("enable_publisher_churn_checks", False):
        return None
    max_changes = int(policy.data.get("max_publisher_changes_90d", 1))
    meta = signals.get(manager, package)
    changes = meta.get("publisher_changes_90d")
    if changes is None:
        return None
    try:
        num = int(changes)
    except Exception:
        return None
    if num > max_changes:
        return Finding(
            "MEDIUM",
            manager,
            "PUBLISHER_CHURN",
            f"Package '{package}' has {num} publisher changes in 90 days (> {max_changes}).",
            file_ref,
            package,
            fix="Investigate maintainer history and require additional trust checks.",
        )
    return None


def maintainer_change_finding(policy, manager: str, package: str, file_ref: str, signals: MetadataSignals):
    if not policy.data.get("enable_maintainer_change_checks", False):
        return None
    max_changes = int(policy.data.get("max_maintainer_changes_180d", 1))
    meta = signals.get(manager, package)
    changes = meta.get("maintainer_changes_180d")
    if changes is None:
        return None
    try:
        num = int(changes)
    except Exception:
        return None
    if num > max_changes:
        return Finding(
            "MEDIUM",
            manager,
            "MAINTAINER_CHANGE_RISK",
            f"Package '{package}' has {num} maintainer changes in 180 days (> {max_changes}).",
            file_ref,
            package,
            fix="Review maintainer transfer history and repository ownership before approval.",
        )
    return None
