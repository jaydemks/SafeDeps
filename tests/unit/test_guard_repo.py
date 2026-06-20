from types import SimpleNamespace

import safedeps.guard_repo as guard_repo


def test_detect_official_repo_url_returns_trimmed_origin(monkeypatch, tmp_path):
    monkeypatch.setattr(
        guard_repo.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=" https://example/repo.git \n"),
    )

    assert guard_repo.detect_official_repo_url(tmp_path) == "https://example/repo.git"


def test_detect_official_repo_url_returns_empty_for_missing_origin(monkeypatch, tmp_path):
    monkeypatch.setattr(
        guard_repo.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""),
    )

    assert guard_repo.detect_official_repo_url(tmp_path) == ""


def test_detect_official_repo_url_returns_empty_when_git_fails(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise OSError("git unavailable")

    monkeypatch.setattr(guard_repo.subprocess, "run", fail)

    assert guard_repo.detect_official_repo_url(tmp_path) == ""
