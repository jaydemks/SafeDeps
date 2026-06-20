import json
from types import SimpleNamespace

import pytest

from safedeps import exceptions


def test_upsert_approval_entry_adds_then_updates_existing_entry(tmp_path):
    updated, message = exceptions.upsert_approval_entry(
        tmp_path,
        ".safedeps/baseline.json",
        "pip",
        "UNPINNED",
        "requests",
        "requirements.txt",
        "2099-01-01",
    )

    assert updated is False
    assert "pip/UNPINNED" in message

    updated, message = exceptions.upsert_approval_entry(
        tmp_path,
        ".safedeps/baseline.json",
        "pip",
        "UNPINNED",
        "requests",
        "requirements.txt",
        "2099-06-01",
    )

    data = json.loads((tmp_path / ".safedeps" / "baseline.json").read_text(encoding="utf-8"))
    assert updated is True
    assert message.endswith("expires=2099-06-01")
    assert len(data["suppress"]) == 1
    assert data["suppress"][0]["expires"] == "2099-06-01"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not-json", "Invalid baseline JSON"),
        ("[]", "expected JSON object"),
        (json.dumps({"suppress": {}}), "suppress must be a list"),
    ],
)
def test_upsert_approval_entry_rejects_invalid_baseline(tmp_path, content, message):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        exceptions.upsert_approval_entry(
            tmp_path,
            "baseline.json",
            "pip",
            "UNPINNED",
            "requests",
            "requirements.txt",
            "2099-01-01",
        )


def test_upsert_approval_entry_validates_required_fields_and_expiry(tmp_path):
    with pytest.raises(ValueError, match="manager and rule"):
        exceptions.upsert_approval_entry(tmp_path, "baseline.json", "", "RULE", "", "", "2099-01-01")

    with pytest.raises(ValueError, match="Invalid expires"):
        exceptions.upsert_approval_entry(tmp_path, "baseline.json", "pip", "RULE", "", "", "tomorrow")


def test_write_baseline_file_converts_report_findings(tmp_path):
    report = tmp_path / "security-artifacts" / "report.json"
    report.parent.mkdir()
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {"manager": "pip", "rule": "UNPINNED", "package": "requests", "file": "requirements.txt"},
                    "ignored",
                ]
            }
        ),
        encoding="utf-8",
    )

    count, output_path = exceptions.write_baseline_file(
        tmp_path,
        "security-artifacts/report.json",
        ".safedeps/baseline.json",
    )

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert count == 1
    assert data == {
        "suppress": [
            {"manager": "pip", "rule": "UNPINNED", "package": "requests", "file": "requirements.txt"}
        ]
    }


@pytest.mark.parametrize(
    ("report_content", "message"),
    [
        (None, "Missing report file"),
        ("not-json", "Invalid report JSON"),
        (json.dumps({"findings": {}}), "findings must be a list"),
    ],
)
def test_write_baseline_file_rejects_invalid_reports(tmp_path, report_content, message):
    if report_content is not None:
        (tmp_path / "report.json").write_text(report_content, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        exceptions.write_baseline_file(tmp_path, "report.json", "baseline.json")


def test_cmd_explain_prints_known_rule_or_unknown_message(capsys):
    assert exceptions.cmd_explain(SimpleNamespace(rule="floating_version")) == 0
    out = capsys.readouterr().out
    assert "FLOATING_VERSION" in out
    assert "Fix:" in out

    assert exceptions.cmd_explain(SimpleNamespace(rule="does-not-exist")) == 2
    assert "Unknown finding rule" in capsys.readouterr().out


@pytest.mark.parametrize("rule", ["DENYLIST", "UNTRUSTED_REGISTRY", "DIRECT_URL", "INSTALL_SCRIPT"])
def test_cmd_explain_covers_emitted_rule_names(rule, capsys):
    assert exceptions.cmd_explain(SimpleNamespace(rule=rule.lower())) == 0
    out = capsys.readouterr().out
    assert rule in out
    assert "Fix:" in out


def test_cmd_baseline_and_approve_return_cli_codes(tmp_path, capsys):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [{"manager": "pip", "rule": "UNPINNED"}]}), encoding="utf-8")

    assert exceptions.cmd_baseline(
        SimpleNamespace(path=str(tmp_path), report="report.json", output=".safedeps/baseline.json")
    ) == 0
    assert "Baseline written" in capsys.readouterr().out

    approve_args = SimpleNamespace(
        path=str(tmp_path),
        baseline=".safedeps/approvals.json",
        manager="pip",
        rule="unpinned",
        package="requests",
        file="requirements.txt",
        expires="2099-01-01",
    )
    assert exceptions.cmd_approve(approve_args) == 0
    assert "Added approval" in capsys.readouterr().out

    approve_args.expires = "2099-06-01"
    assert exceptions.cmd_approve(approve_args) == 0
    assert "Updated approval" in capsys.readouterr().out

    approve_args.expires = "invalid"
    assert exceptions.cmd_approve(approve_args) == 2
    assert "Invalid expires" in capsys.readouterr().out
