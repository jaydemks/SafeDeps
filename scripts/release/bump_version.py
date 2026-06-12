#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write(path: Path, text: str, dry_run: bool) -> None:
    if dry_run:
        return
    path.write_text(text, encoding="utf-8")


def current_version() -> str:
    text = read(ROOT / "pyproject.toml")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', text)
    if not match:
        raise ValueError("Unable to find project.version in pyproject.toml")
    version = match.group(1)
    if not VERSION_RE.match(version):
        raise ValueError(f"Unsupported current version format: {version}")
    return version


def next_version(current: str, bump: str) -> str:
    if VERSION_RE.match(bump):
        return bump
    major, minor, patch = [int(part) for part in current.split(".")]
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"Unknown bump target: {bump}")


def replace_required(path: Path, pattern: str, replacement: str, dry_run: bool) -> None:
    text = read(path)
    new_text, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f"Expected exactly one match in {path.relative_to(ROOT)}")
    write(path, new_text, dry_run)


def update_versions(version: str, dry_run: bool) -> list[str]:
    changed: list[str] = []

    replace_required(ROOT / "pyproject.toml", r'^version\s*=\s*"[^"]+"\s*$', f'version = "{version}"', dry_run)
    changed.append("pyproject.toml")

    replace_required(ROOT / "safedeps" / "__init__.py", r'^__version__\s*=\s*"[^"]+"\s*$', f'__version__ = "{version}"', dry_run)
    changed.append("safedeps/__init__.py")

    package_path = ROOT / "packages" / "npm-wrapper" / "package.json"
    package = json.loads(read(package_path))
    package["version"] = version
    write(package_path, json.dumps(package, indent=2) + "\n", dry_run)
    changed.append("packages/npm-wrapper/package.json")

    replace_required(
        ROOT / "packages" / "dotnet-tool" / "SafeDeps.Tool.csproj",
        r"<PackageVersion>\s*[^<]+\s*</PackageVersion>",
        f"<PackageVersion>{version}</PackageVersion>",
        dry_run,
    )
    changed.append("packages/dotnet-tool/SafeDeps.Tool.csproj")

    readme = ROOT / "README.md"
    text = read(readme)
    new_text = re.sub(r"--expected-version\s+\d+\.\d+\.\d+", f"--expected-version {version}", text)
    if new_text != text:
        write(readme, new_text, dry_run)
        changed.append("README.md")

    return changed


def release_note_text(version: str, notes: list[str], today: str) -> str:
    bullet_lines = "\n".join(f"- {note}" for note in notes) if notes else "- TODO: summarize release changes."
    return f"""# SafeDeps {version} - Release Notes ({today})

## Scope

TODO: short summary of this release.

## Changed

{bullet_lines}

## Verification

- TODO: list commands/tests executed before release.

## Follow-up Queue

- TODO: list known follow-up work, if any.
"""


def update_release_note(version: str, notes: list[str], today: str, dry_run: bool) -> Path:
    path = ROOT / f"RELEASE_NOTES_{today}.md"
    if not path.exists():
        write(path, release_note_text(version, notes, today), dry_run)
        return path

    text = read(path)
    if f"SafeDeps {version}" in text:
        return path

    bullet_lines = "\n".join(f"- {note}" for note in notes) if notes else "- TODO: summarize release changes."
    addition = f"""

## SafeDeps {version} - Update

### Changed

{bullet_lines}

### Verification

- TODO: list commands/tests executed before release.
"""
    write(path, text.rstrip() + addition, dry_run)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Bump SafeDeps versions and prepare release notes.")
    parser.add_argument("bump", help="patch, minor, major, or explicit X.Y.Z version")
    parser.add_argument("--note", action="append", default=[], help="Release note bullet. Can be passed multiple times.")
    parser.add_argument("--date", default=date.today().isoformat(), help="Release note date, default: today")
    parser.add_argument("--no-release-note", action="store_true", help="Only bump version files.")
    parser.add_argument("--dry-run", action="store_true", help="Print intended changes without writing files.")
    args = parser.parse_args()

    current = current_version()
    target = next_version(current, args.bump)
    if target == current:
        raise SystemExit(f"Version is already {target}")

    changed = update_versions(target, args.dry_run)
    release_note = None
    if not args.no_release_note:
        release_note = update_release_note(target, args.note, args.date, args.dry_run)
        changed.append(str(release_note.relative_to(ROOT)))

    action = "Would bump" if args.dry_run else "Bumped"
    print(f"{action} SafeDeps {current} -> {target}")
    for item in changed:
        print(f"- {item}")
    if release_note:
        print(f"Release note: {release_note.relative_to(ROOT)}")
    print(f"Next check: python scripts/release/preflight.py --expected-version {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
