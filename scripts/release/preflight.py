#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def version_from_pyproject() -> str:
    txt = read(ROOT / "pyproject.toml")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', txt)
    if not m:
        raise ValueError("pyproject.toml missing project.version")
    return m.group(1)


def version_from_init() -> str:
    txt = read(ROOT / "safedeps" / "__init__.py")
    m = re.search(r'(?m)^__version__\s*=\s*"([^"]+)"\s*$', txt)
    if not m:
        raise ValueError("safedeps/__init__.py missing __version__")
    return m.group(1)


def version_from_npm() -> str:
    data = json.loads(read(ROOT / "packages" / "npm-wrapper" / "package.json"))
    v = str(data.get("version", "")).strip()
    if not v:
        raise ValueError("packages/npm-wrapper/package.json missing version")
    return v


def version_from_dotnet_tool() -> str:
    txt = read(ROOT / "packages" / "dotnet-tool" / "SafeDeps.Tool.csproj")
    m = re.search(r"(?m)<PackageVersion>\s*([^<]+)\s*</PackageVersion>\s*$", txt)
    if not m:
        raise ValueError("packages/dotnet-tool/SafeDeps.Tool.csproj missing PackageVersion")
    return m.group(1).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="SafeDeps release preflight checks")
    parser.add_argument("--expected-version", default="", help="Expected release version (e.g. 0.2.1)")
    parser.add_argument("--require-tag", action="store_true", help="Require git ref/tag to match v<version>")
    args = parser.parse_args()

    errors: list[str] = []

    try:
        versions = {
            "pyproject": version_from_pyproject(),
            "python": version_from_init(),
            "npm": version_from_npm(),
            "dotnet_tool": version_from_dotnet_tool(),
        }
    except Exception as exc:
        print(f"preflight: failed to read versions: {exc}")
        return 2

    if len(set(versions.values())) != 1:
        errors.append(f"version mismatch: {versions}")
    version = next(iter(set(versions.values())))

    expected = str(args.expected_version).strip()
    if expected and version != expected:
        errors.append(f"expected version {expected}, found {version}")

    if args.require_tag:
        tag = str(os.environ.get("GITHUB_REF_NAME", "")).strip()
        expected_tag = f"v{version}"
        if tag != expected_tag:
            errors.append(f"release tag mismatch: expected {expected_tag}, got {tag or '<empty>'}")

    required_paths = [
        ROOT / ".github" / "workflows" / "safedeps.yml",
        ROOT / "scripts" / "validate_artifacts.py",
        ROOT / "scripts" / "release" / "create_release_manifest.py",
        ROOT / "packages" / "dotnet-tool" / "SafeDeps.Tool.csproj",
        ROOT / "README.md",
        ROOT / "RELEASE_NOTES_2026-05-22.md",
    ]
    for p in required_paths:
        if not p.exists():
            errors.append(f"missing required file: {p.relative_to(ROOT)}")

    if not errors:
        print(f"preflight: PASS version={version}")
        return 0

    print("preflight: FAIL")
    for e in errors:
        print(f"- {e}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
