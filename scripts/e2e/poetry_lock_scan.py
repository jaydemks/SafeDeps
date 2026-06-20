#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(args: list[str], cwd: Path, *, expect: int = 0) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, cwd=str(cwd), text=True, capture_output=True)
    if proc.returncode != expect:
        print(f"command failed: {' '.join(args)}", file=sys.stderr)
        print(f"cwd: {cwd}", file=sys.stderr)
        print(f"expected exit code: {expect}, got: {proc.returncode}", file=sys.stderr)
        if proc.stdout:
            print("stdout:", file=sys.stderr)
            print(proc.stdout, file=sys.stderr)
        if proc.stderr:
            print("stderr:", file=sys.stderr)
            print(proc.stderr, file=sys.stderr)
        raise SystemExit(1)
    return proc


def write_poetry_project(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        """
[tool.poetry]
name = "safedeps-poetry-e2e"
version = "0.0.1"
description = "SafeDeps Poetry compatibility fixture"
authors = ["SafeDeps <security@example.invalid>"]

[tool.poetry.dependencies]
python = ">=3.10,<4.0"
requests = "2.32.3"

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    policy_dir = root / ".safedeps"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "policy.json").write_text(
        json.dumps({"allow_unpinned": False, "require_lockfiles": True}, indent=2),
        encoding="utf-8",
    )


def read_report(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"cannot read SafeDeps report {path}: {exc}") from exc


def assert_poetry_report(report: dict, *, expect_denylist: bool) -> None:
    findings = report.get("findings", [])
    rules = {finding.get("rule") for finding in findings}
    components = report.get("sbom", {}).get("components", [])
    names = {component.get("name") for component in components}

    if "requests" not in names:
        raise SystemExit(f"expected poetry.lock component 'requests', got: {sorted(names)}")
    if "MISSING_LOCKFILE" in rules:
        raise SystemExit("poetry.lock was present but SafeDeps reported MISSING_LOCKFILE")
    if expect_denylist and "DENYLIST" not in rules:
        raise SystemExit(f"expected DENYLIST finding, got rules: {sorted(r for r in rules if r)}")
    if not expect_denylist and rules:
        raise SystemExit(f"expected safe Poetry project, got findings: {findings}")


def main() -> int:
    if shutil.which("poetry") is None:
        raise SystemExit("poetry executable is not available on PATH")

    with tempfile.TemporaryDirectory(prefix="safedeps-poetry-e2e-") as raw:
        root = Path(raw)
        write_poetry_project(root)

        env = os.environ.copy()
        env["POETRY_VIRTUALENVS_CREATE"] = "false"
        run(["poetry", "--version"], root)
        subprocess.run(["poetry", "lock", "--no-interaction"], cwd=str(root), env=env, check=True)

        safe_out = root / "safe-artifacts"
        run(
            [
                sys.executable,
                "-m",
                "safedeps.cli",
                "scan",
                str(root),
                "--fail-on",
                "HIGH",
                "--out",
                str(safe_out),
            ],
            root,
        )
        assert_poetry_report(read_report(safe_out / "safedeps-report.json"), expect_denylist=False)

        policy = root / ".safedeps" / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "allow_unpinned": False,
                    "require_lockfiles": True,
                    "deny_packages": ["requests"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        deny_out = root / "deny-artifacts"
        run(
            [
                sys.executable,
                "-m",
                "safedeps.cli",
                "scan",
                str(root),
                "--fail-on",
                "HIGH",
                "--out",
                str(deny_out),
            ],
            root,
            expect=2,
        )
        assert_poetry_report(read_report(deny_out / "safedeps-report.json"), expect_denylist=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
