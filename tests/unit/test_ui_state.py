import json

import pytest

from safedeps.ui_state import (
    _ui_state_from_form,
    create_intelligence_templates,
    default_ui_state,
    load_intelligence_into_state,
    save_intelligence_from_state,
)


def test_default_ui_state_uses_scan_path_and_fail_threshold(tmp_path):
    state = default_ui_state(tmp_path, "MEDIUM")

    assert state["path"] == str(tmp_path)
    assert state["fail_on"] == "MEDIUM"
    assert state["out"] == "security-artifacts"
    assert not state["online_audit"]


def test_ui_state_from_form_normalizes_values(tmp_path):
    form = {
        "out": [" custom-out "],
        "policy": [" policy.json "],
        "online_audit": ["on"],
        "rule": [" floating_version "],
        "approve_rule": [" direct_url "],
        "manager": ["pip"],
        "package": [" requests "],
        "file_value": [" requirements.txt "],
        "expires": [" 2026-12-31 "],
    }

    state = _ui_state_from_form(form, tmp_path, "NOT_A_SEVERITY")

    assert state["fail_on"] == "HIGH"
    assert state["out"] == "custom-out"
    assert state["policy"] == "policy.json"
    assert state["online_audit"]
    assert state["rule"] == "FLOATING_VERSION"
    assert state["approve_rule"] == "DIRECT_URL"
    assert state["package"] == "requests"
    assert state["file_value"] == "requirements.txt"


def test_create_and_load_intelligence_templates(tmp_path):
    create_intelligence_templates(tmp_path)

    state = load_intelligence_into_state(default_ui_state(tmp_path, "HIGH"), tmp_path)

    assert json.loads(state["vuln_feed_json"]) == {
        "vulnerabilities": [],
        "vulnerabilities_osv": [],
    }
    assert json.loads(state["metadata_cache_json"]) == {"packages": []}


def test_load_intelligence_keeps_existing_state_values(tmp_path):
    state = {
        "vuln_feed_json": '{"custom": true}',
        "metadata_cache_json": '{"custom": true}',
    }

    loaded = load_intelligence_into_state(state, tmp_path)

    assert loaded["vuln_feed_json"] == '{"custom": true}'
    assert loaded["metadata_cache_json"] == '{"custom": true}'


def test_save_intelligence_from_state_writes_valid_json(tmp_path):
    save_intelligence_from_state(
        tmp_path,
        {
            "vuln_feed_json": '{"vulnerabilities": [{"id": "CVE-1"}]}',
            "metadata_cache_json": '{"packages": [{"name": "requests"}]}',
        },
    )

    assert json.loads((tmp_path / ".safedeps" / "vuln-feed.json").read_text(encoding="utf-8"))[
        "vulnerabilities"
    ] == [{"id": "CVE-1"}]
    assert json.loads((tmp_path / ".safedeps" / "metadata-cache.json").read_text(encoding="utf-8"))[
        "packages"
    ] == [{"name": "requests"}]


@pytest.mark.parametrize(
    ("state", "message"),
    [
        ({"vuln_feed_json": "", "metadata_cache_json": "{}"}, "Vulnerability feed JSON cannot be empty."),
        ({"vuln_feed_json": "[]", "metadata_cache_json": "{}"}, "Vulnerability feed must be a JSON object."),
        ({"vuln_feed_json": "{}", "metadata_cache_json": ""}, "Metadata cache JSON cannot be empty."),
        ({"vuln_feed_json": "{}", "metadata_cache_json": "[]"}, "Metadata cache must be a JSON object."),
    ],
)
def test_save_intelligence_from_state_rejects_invalid_payloads(tmp_path, state, message):
    with pytest.raises(ValueError, match=message):
        save_intelligence_from_state(tmp_path, state)
