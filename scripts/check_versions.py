#!/usr/bin/env python3
"""Fail CI if package versions are inconsistent across distributions."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
PY_INIT = ROOT / "safedeps" / "__init__.py"
NPM_PACKAGE = ROOT / "packages" / "npm-wrapper" / "package.json"
DOTNET_TOOL_PROJECT = ROOT / "packages" / "dotnet-tool" / "SafeDeps.Tool.csproj"


def _extract_pyproject_version(content: str) -> str:
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', content)
    if not match:
        raise ValueError("Unable to find project.version in pyproject.toml")
    return match.group(1)


def _extract_init_version(content: str) -> str:
    match = re.search(r'(?m)^__version__\s*=\s*"([^"]+)"\s*$', content)
    if not match:
        raise ValueError("Unable to find __version__ in safedeps/__init__.py")
    return match.group(1)


def main() -> int:
    try:
        pyproject_version = _extract_pyproject_version(PYPROJECT.read_text(encoding="utf-8"))
        init_version = _extract_init_version(PY_INIT.read_text(encoding="utf-8"))
        npm_version = json.loads(NPM_PACKAGE.read_text(encoding="utf-8"))["version"]
        dotnet_match = re.search(
            r"(?m)<PackageVersion>\s*([^<]+)\s*</PackageVersion>\s*$",
            DOTNET_TOOL_PROJECT.read_text(encoding="utf-8"),
        )
        if not dotnet_match:
            raise ValueError("Unable to find <PackageVersion> in packages/dotnet-tool/SafeDeps.Tool.csproj")
        dotnet_version = dotnet_match.group(1).strip()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Version check failed while reading files: {exc}", file=sys.stderr)
        return 1

    versions = {
        "pyproject.toml": pyproject_version,
        "safedeps/__init__.py": init_version,
        "packages/npm-wrapper/package.json": npm_version,
        "packages/dotnet-tool/SafeDeps.Tool.csproj": dotnet_version,
    }

    unique_versions = set(versions.values())
    if len(unique_versions) != 1:
        print("Version mismatch detected:", file=sys.stderr)
        for file_name, version in versions.items():
            print(f"- {file_name}: {version}", file=sys.stderr)
        return 2

    only_version = unique_versions.pop()
    print(f"Version consistency check passed: {only_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
