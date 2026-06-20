import datetime
import json

import pytest

from safedeps.policy import DEFAULT_POLICY, Policy, PolicyValidationError, deep_update


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


def test_deep_update_preserves_unmentioned_nested_values():
    data = {"outer": {"a": 1, "b": 2}, "keep": True}

    result = deep_update(data, {"outer": {"b": 3}})

    assert result == {"outer": {"a": 1, "b": 3}, "keep": True}
