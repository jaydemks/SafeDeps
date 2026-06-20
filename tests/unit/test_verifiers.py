import datetime as dt

from safedeps.models import Finding
from safedeps.policy import Policy
from safedeps.scanners.metadata_signals import MetadataSignals, supply_chain_signal_findings
from safedeps.verifiers import PackageVerificationContext, verify_package


def test_verify_package_runs_default_supply_chain_verifiers():
    published = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    policy = Policy(
        {
            "enable_package_age_checks": True,
            "min_package_age_days": 14,
            "enable_publisher_churn_checks": True,
            "max_publisher_changes_90d": 1,
            "enable_maintainer_change_checks": True,
            "max_maintainer_changes_180d": 1,
        }
    )
    signals = MetadataSignals(
        {
            "npm": {
                "requests": {
                    "published": published,
                    "publisher_changes_90d": 3,
                    "maintainer_changes_180d": 2,
                }
            }
        }
    )

    rules = [
        finding.rule
        for finding in verify_package(policy, "npm", "requests", "package.json", signals)
    ]

    assert rules == ["PACKAGE_TOO_NEW", "PUBLISHER_CHURN", "MAINTAINER_CHANGE_RISK"]


def test_verify_package_accepts_custom_verifier_pipeline():
    class CustomVerifier:
        name = "custom"

        def verify(self, policy, context: PackageVerificationContext):
            return [
                Finding(
                    "LOW",
                    context.manager,
                    "CUSTOM_VERIFIER",
                    f"Checked {context.package}",
                    context.file_ref,
                    context.package,
                )
            ]

    findings = verify_package(
        Policy({}),
        "pip",
        "requests",
        "requirements.txt",
        MetadataSignals({}),
        verifiers=(CustomVerifier(),),
    )

    assert [finding.rule for finding in findings] == ["CUSTOM_VERIFIER"]
    assert findings[0].package == "requests"


def test_legacy_supply_chain_signal_helper_delegates_to_verifier_interface():
    policy = Policy({"enable_package_age_checks": True, "min_package_age_days": 14})
    published = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    signals = MetadataSignals({"pip": {"requests": {"published": published}}})

    findings = supply_chain_signal_findings(
        policy,
        "pip",
        "requests",
        "requirements.txt",
        signals,
    )

    assert [finding.rule for finding in findings] == ["PACKAGE_TOO_NEW"]
