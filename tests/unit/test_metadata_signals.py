import datetime as dt
import json

from safedeps.policy import Policy
from safedeps.scanners.metadata_signals import (
    MetadataSignals,
    age_finding,
    churn_finding,
    download_anomaly_finding,
    maintainer_change_finding,
    repository_link_finding,
    supply_chain_signal_findings,
)


def test_metadata_signals_loads_missing_invalid_and_non_dict_values(tmp_path):
    assert MetadataSignals.load(tmp_path).data == {}

    cache = tmp_path / ".safedeps" / "metadata-cache.json"
    cache.parent.mkdir()
    cache.write_text("{ invalid", encoding="utf-8")
    assert MetadataSignals.load(tmp_path).data == {}

    cache.write_text(json.dumps({"pip": {"requests": {"published": "2026-01-01"}}}), encoding="utf-8")
    signals = MetadataSignals.load(tmp_path)
    assert signals.get("pip", "requests") == {"published": "2026-01-01"}
    assert MetadataSignals({"pip": []}).get("pip", "requests") == {}
    assert MetadataSignals({"pip": {"requests": []}}).get("pip", "requests") == {}


def test_age_finding_reports_packages_newer_than_policy_threshold():
    published = (dt.date.today() - dt.timedelta(days=2)).isoformat()
    policy = Policy(
        {
            "enable_package_age_checks": True,
            "min_package_age_days": 14,
            "metadata_risk_severity": "HIGH",
        }
    )
    signals = MetadataSignals({"pip": {"requests": {"published": published}}})

    finding = age_finding(policy, "pip", "requests", "requirements.txt", signals)

    assert finding is not None
    assert finding.rule == "PACKAGE_TOO_NEW"
    assert finding.package == "requests"
    assert finding.severity == "HIGH"


def test_age_finding_ignores_disabled_invalid_missing_and_old_packages():
    today = dt.date.today()
    signals = MetadataSignals(
        {
            "pip": {
                "missing-date": {},
                "invalid-date": {"published": "not-a-date"},
                "old": {"published": (today - dt.timedelta(days=90)).isoformat()},
            }
        }
    )

    assert age_finding(Policy({}), "pip", "old", "requirements.txt", signals) is None
    assert (
        age_finding(
            Policy({"enable_package_age_checks": True, "min_package_age_days": 0}),
            "pip",
            "old",
            "requirements.txt",
            signals,
        )
        is None
    )
    policy = Policy({"enable_package_age_checks": True, "min_package_age_days": 14})
    assert age_finding(policy, "pip", "missing-date", "requirements.txt", signals) is None
    assert age_finding(policy, "pip", "invalid-date", "requirements.txt", signals) is None
    assert age_finding(policy, "pip", "old", "requirements.txt", signals) is None


def test_churn_finding_reports_publisher_churn_above_threshold():
    policy = Policy({"enable_publisher_churn_checks": True, "max_publisher_changes_90d": 1})
    signals = MetadataSignals({"npm": {"lodash": {"publisher_changes_90d": "3"}}})

    finding = churn_finding(policy, "npm", "lodash", "package.json", signals)

    assert finding is not None
    assert finding.rule == "PUBLISHER_CHURN"


def test_churn_finding_ignores_disabled_missing_invalid_and_below_threshold():
    signals = MetadataSignals(
        {
            "npm": {
                "missing": {},
                "invalid": {"publisher_changes_90d": "many"},
                "stable": {"publisher_changes_90d": 1},
            }
        }
    )
    policy = Policy({"enable_publisher_churn_checks": True, "max_publisher_changes_90d": 1})

    assert churn_finding(Policy({}), "npm", "stable", "package.json", signals) is None
    assert churn_finding(policy, "npm", "missing", "package.json", signals) is None
    assert churn_finding(policy, "npm", "invalid", "package.json", signals) is None
    assert churn_finding(policy, "npm", "stable", "package.json", signals) is None


def test_maintainer_change_finding_reports_and_ignores_expected_cases():
    signals = MetadataSignals(
        {
            "nuget": {
                "Risky.Package": {"maintainer_changes_180d": 4},
                "Stable.Package": {"maintainer_changes_180d": 1},
                "Invalid.Package": {"maintainer_changes_180d": "many"},
                "Missing.Package": {},
            }
        }
    )
    policy = Policy({"enable_maintainer_change_checks": True, "max_maintainer_changes_180d": 1})

    finding = maintainer_change_finding(
        policy,
        "nuget",
        "Risky.Package",
        "Directory.Packages.props",
        signals,
    )

    assert finding is not None
    assert finding.rule == "MAINTAINER_CHANGE_RISK"
    assert maintainer_change_finding(Policy({}), "nuget", "Risky.Package", "", signals) is None
    assert maintainer_change_finding(policy, "nuget", "Stable.Package", "", signals) is None
    assert maintainer_change_finding(policy, "nuget", "Invalid.Package", "", signals) is None
    assert maintainer_change_finding(policy, "nuget", "Missing.Package", "", signals) is None


def test_repository_link_finding_reports_missing_repository_metadata():
    signals = MetadataSignals(
        {
            "pip": {
                "missing-repo": {},
                "has-repo": {"repository_url": "https://example.test/repo"},
            }
        }
    )
    policy = Policy({"enable_repository_link_checks": True, "metadata_risk_severity": "HIGH"})

    finding = repository_link_finding(policy, "pip", "missing-repo", "requirements.txt", signals)

    assert finding is not None
    assert finding.rule == "MISSING_REPOSITORY_LINK"
    assert finding.severity == "HIGH"
    assert repository_link_finding(policy, "pip", "has-repo", "requirements.txt", signals) is None
    assert repository_link_finding(Policy({}), "pip", "missing-repo", "requirements.txt", signals) is None


def test_download_anomaly_finding_reports_low_download_metadata():
    signals = MetadataSignals(
        {
            "npm": {
                "quiet": {"downloads_30d": "3"},
                "popular": {"downloads_30d": 1000},
                "unknown": {},
                "invalid": {"downloads_30d": "many"},
            }
        }
    )
    policy = Policy({"enable_download_anomaly_checks": True, "min_downloads_30d": 25})

    finding = download_anomaly_finding(policy, "npm", "quiet", "package.json", signals)

    assert finding is not None
    assert finding.rule == "LOW_DOWNLOAD_SIGNAL"
    assert download_anomaly_finding(policy, "npm", "popular", "package.json", signals) is None
    assert download_anomaly_finding(policy, "npm", "unknown", "package.json", signals) is None
    assert download_anomaly_finding(policy, "npm", "invalid", "package.json", signals) is None
    assert (
        download_anomaly_finding(
            Policy({"enable_download_anomaly_checks": True, "min_downloads_30d": 0}),
            "npm",
            "quiet",
            "package.json",
            signals,
        )
        is None
    )


def test_supply_chain_signal_findings_collects_enabled_common_verifiers():
    published = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    policy = Policy(
        {
            "enable_package_age_checks": True,
            "min_package_age_days": 14,
            "enable_publisher_churn_checks": True,
            "max_publisher_changes_90d": 1,
            "enable_maintainer_change_checks": True,
            "max_maintainer_changes_180d": 1,
            "enable_repository_link_checks": True,
            "enable_download_anomaly_checks": True,
            "min_downloads_30d": 25,
        }
    )
    signals = MetadataSignals(
        {
            "npm": {
                "requests": {
                    "published": published,
                    "publisher_changes_90d": 3,
                    "maintainer_changes_180d": 2,
                    "downloads_30d": 3,
                }
            }
        }
    )

    rules = [
        finding.rule
        for finding in supply_chain_signal_findings(policy, "npm", "requests", "package.json", signals)
    ]

    assert rules == [
        "PACKAGE_TOO_NEW",
        "PUBLISHER_CHURN",
        "MAINTAINER_CHANGE_RISK",
        "MISSING_REPOSITORY_LINK",
        "LOW_DOWNLOAD_SIGNAL",
    ]
