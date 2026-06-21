import datetime
import json

import pytest

from safedeps.policy import (
    DEFAULT_POLICY,
    Policy,
    PolicyValidationError,
    deep_update,
    validate_policy_schema_v1,
)


def test_policy_load_merges_nested_defaults(tmp_path):
    policy_dir = tmp_path / ".safedeps"
    policy_dir.mkdir()
    policy_file = policy_dir / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "allowed_registries": {"pip": ["https://internal.example/simple"]},
                "deny_packages": ["danger"],
            }
        ),
        encoding="utf-8",
    )

    policy = Policy.load(tmp_path)

    assert policy.path == policy_file
    assert policy.data["allowed_registries"]["pip"] == ["https://internal.example/simple"]
    assert policy.data["allowed_registries"]["npm"] == DEFAULT_POLICY["allowed_registries"]["npm"]
    assert policy.is_denied("Danger")


def test_policy_load_uses_explicit_file_and_default_when_missing(tmp_path):
    explicit = tmp_path / "custom-policy.json"
    explicit.write_text(
        json.dumps(
            {
                "schema": "safedeps.policy.v1",
                "deny_packages": ["blocked-demo"],
            }
        ),
        encoding="utf-8",
    )

    policy = Policy.load(tmp_path, str(explicit))

    assert policy.path == explicit
    assert policy.is_denied("blocked-demo")
    assert Policy.load(tmp_path / "missing").path is None


def test_policy_load_rejects_invalid_core_policy_types(tmp_path):
    policy_dir = tmp_path / ".safedeps"
    policy_dir.mkdir()
    policy_file = policy_dir / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "schema": "safedeps.policy.v1",
                "allowed_registries": {"pip": "https://internal.example/simple"},
                "deny_packages": ["danger", ""],
                "allow_unpinned": "false",
                "require_lockfiles": "true",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PolicyValidationError) as excinfo:
        Policy.load(tmp_path)

    message = str(excinfo.value)
    assert "policy.allowed_registries.pip must be a list of registry URLs" in message
    assert "policy.deny_packages[1] must be a non-empty string" in message
    assert "policy.allow_unpinned must be true or false" in message
    assert "policy.require_lockfiles must be true or false" in message


def test_policy_load_rejects_invalid_schema_and_container_shapes(tmp_path):
    policy_dir = tmp_path / ".safedeps"
    policy_dir.mkdir()
    (policy_dir / "policy.json").write_text(
        json.dumps(
            {
                "schema": "other.schema",
                "allowed_registries": "bad",
                "deny_packages": "bad",
                "exceptions": "bad",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PolicyValidationError) as excinfo:
        Policy.load(tmp_path)

    message = str(excinfo.value)
    assert "policy.schema must be 'safedeps.policy.v1'" in message
    assert "policy.allowed_registries must be an object" in message
    assert "policy.deny_packages must be a list" in message
    assert "policy.exceptions must be a list" in message


def test_policy_load_rejects_invalid_registry_keys_and_urls(tmp_path):
    policy_dir = tmp_path / ".safedeps"
    policy_dir.mkdir()
    (policy_dir / "policy.json").write_text(
        json.dumps(
            {
                "allowed_registries": {
                    "": ["https://example.test/simple"],
                    "pip": ["", 3],
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PolicyValidationError) as excinfo:
        Policy.load(tmp_path)

    message = str(excinfo.value)
    assert "policy.allowed_registries keys must be non-empty strings" in message
    assert "policy.allowed_registries.pip[0] must be a non-empty string" in message
    assert "policy.allowed_registries.pip[1] must be a non-empty string" in message


def test_validate_policy_schema_rejects_non_object_policy():
    assert validate_policy_schema_v1([]) == ["policy.json must be a JSON object."]


def test_policy_load_rejects_invalid_metadata_thresholds(tmp_path):
    policy_dir = tmp_path / ".safedeps"
    policy_dir.mkdir()
    (policy_dir / "policy.json").write_text(
        json.dumps(
            {
                "schema": "safedeps.policy.v1",
                "enable_package_age_checks": "yes",
                "min_package_age_days": -1,
                "max_publisher_changes_90d": True,
                "max_maintainer_changes_180d": "1",
                "enable_repository_link_checks": 1,
                "enable_download_anomaly_checks": "yes",
                "min_downloads_30d": -1,
                "advisory_severity_threshold": "urgent",
                "metadata_risk_severity": 3,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(PolicyValidationError) as excinfo:
        Policy.load(tmp_path)

    message = str(excinfo.value)
    assert "policy.enable_package_age_checks must be true or false" in message
    assert "policy.min_package_age_days must be a non-negative integer" in message
    assert "policy.max_publisher_changes_90d must be a non-negative integer" in message
    assert "policy.max_maintainer_changes_180d must be a non-negative integer" in message
    assert "policy.enable_repository_link_checks must be true or false" in message
    assert "policy.enable_download_anomaly_checks must be true or false" in message
    assert "policy.min_downloads_30d must be a non-negative integer" in message
    assert "policy.advisory_severity_threshold must be one of INFO, LOW, MEDIUM, HIGH, or CRITICAL" in message
    assert "policy.metadata_risk_severity must be one of INFO, LOW, MEDIUM, HIGH, or CRITICAL" in message


def test_policy_expiring_exception_matches_until_expiry():
    tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
    policy = Policy(
        {
            "require_expiring_exceptions": True,
            "exceptions": [
                {
                    "manager": "pip",
                    "package": "requests",
                    "rule": "FLOATING_VERSION",
                    "expires": tomorrow,
                }
            ],
        }
    )

    assert policy.has_exception("pip", "requests", "FLOATING_VERSION")


def test_policy_exception_matching_rejects_non_matching_and_non_expiring_entries():
    policy = Policy(
        {
            "require_expiring_exceptions": True,
            "exceptions": [
                {"manager": "npm", "package": "requests", "rule": "FLOATING_VERSION", "expires": "2099-01-01"},
                {"manager": "pip", "package": "lodash", "rule": "FLOATING_VERSION", "expires": "2099-01-01"},
                {"manager": "pip", "package": "requests", "rule": "DENYLIST", "expires": "2099-01-01"},
                {"manager": "pip", "package": "requests", "rule": "FLOATING_VERSION"},
            ],
        }
    )

    assert not policy.has_exception("pip", "requests", "FLOATING_VERSION")


def test_policy_non_expiring_exception_can_match_when_allowed():
    policy = Policy(
        {
            "require_expiring_exceptions": False,
            "exceptions": [
                {"manager": "pip", "package": "requests", "rule": "FLOATING_VERSION"},
            ],
        }
    )

    assert policy.has_exception("pip", "requests", "FLOATING_VERSION")


def test_policy_expired_exception_is_ignored():
    yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    policy = Policy(
        {
            "require_expiring_exceptions": True,
            "exceptions": [
                {
                    "manager": "*",
                    "package": "*",
                    "rule": "*",
                    "expires": yesterday,
                }
            ],
        }
    )

    assert not policy.has_exception("npm", "lodash", "FLOATING_VERSION")


def test_validate_policy_schema_accepts_valid_optional_controls():
    assert (
        validate_policy_schema_v1(
            {
                "min_package_age_days": 0,
                "advisory_severity_threshold": "critical",
                "metadata_risk_severity": "info",
            }
        )
        == []
    )


def test_deep_update_preserves_unmentioned_nested_values():
    data = {"outer": {"a": 1, "b": 2}, "keep": True}

    result = deep_update(data, {"outer": {"b": 3}})

    assert result == {"outer": {"a": 1, "b": 3}, "keep": True}
