from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from safedeps.models import Finding

VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


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


def metadata_risk_severity(policy) -> str:
    severity = str(policy.data.get("metadata_risk_severity", "MEDIUM")).upper()
    return severity if severity in VALID_SEVERITIES else "MEDIUM"


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
            metadata_risk_severity(policy),
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
            metadata_risk_severity(policy),
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
            metadata_risk_severity(policy),
            manager,
            "MAINTAINER_CHANGE_RISK",
            f"Package '{package}' has {num} maintainer changes in 180 days (> {max_changes}).",
            file_ref,
            package,
            fix="Review maintainer transfer history and repository ownership before approval.",
        )
    return None


def repository_link_finding(policy, manager: str, package: str, file_ref: str, signals: MetadataSignals):
    if not policy.data.get("enable_repository_link_checks", False):
        return None
    meta = signals.get(manager, package)
    repository = _first_metadata_string(meta, ("repository_url", "repository", "repo_url", "source_url"))
    if repository:
        return None
    return Finding(
        metadata_risk_severity(policy),
        manager,
        "MISSING_REPOSITORY_LINK",
        f"Package '{package}' has no repository link in local metadata.",
        file_ref,
        package,
        fix="Require manual review or enrich metadata before approval.",
    )


def download_anomaly_finding(policy, manager: str, package: str, file_ref: str, signals: MetadataSignals):
    if not policy.data.get("enable_download_anomaly_checks", False):
        return None
    min_downloads = int(policy.data.get("min_downloads_30d", 25))
    if min_downloads <= 0:
        return None
    meta = signals.get(manager, package)
    downloads = _first_metadata_int(meta, ("downloads_30d", "downloads_last_30_days", "monthly_downloads"))
    if downloads is None or downloads >= min_downloads:
        return None
    return Finding(
        metadata_risk_severity(policy),
        manager,
        "LOW_DOWNLOAD_SIGNAL",
        f"Package '{package}' has {downloads} downloads in 30 days (< {min_downloads}).",
        file_ref,
        package,
        fix="Treat low-download packages as higher risk until publisher and source are reviewed.",
    )


def supply_chain_signal_findings(
    policy,
    manager: str,
    package: str,
    file_ref: str,
    signals: MetadataSignals,
) -> list[Finding]:
    from safedeps.verifiers import verify_package

    return verify_package(policy, manager, package, file_ref, signals)


def _first_metadata_string(meta: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = str(meta.get(key, "")).strip()
        if value:
            return value
    return ""


def _first_metadata_int(meta: dict, keys: tuple[str, ...]) -> int | None:
    for key in keys:
        if key not in meta:
            continue
        try:
            return int(meta[key])
        except Exception:
            continue
    return None
