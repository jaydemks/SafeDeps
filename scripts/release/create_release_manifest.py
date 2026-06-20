#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def collect_files(root: Path) -> list[Path]:
    patterns = [
        "dist/*",
        "packages/npm-wrapper/*.tgz",
        "artifacts/dotnet/*.nupkg",
    ]
    files: list[Path] = []
    for pattern in patterns:
        files.extend(p for p in root.glob(pattern) if p.is_file())
    # deterministic ordering for reproducible manifests
    return sorted(files, key=lambda p: str(p.relative_to(root)))


def artifact_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def main() -> int:
    parser = argparse.ArgumentParser(description="Create release artifact manifest with SHA256 checksums")
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--version", required=True, help="Release version")
    parser.add_argument("--output", default="release-artifacts/release-manifest.json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    files = collect_files(root)

    entries = []
    for f in files:
        entries.append({
            "path": artifact_path(root, f),
            "size": f.stat().st_size,
            "sha256": sha256_file(f),
        })

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "version": str(args.version).strip(),
        "artifacts": entries,
    }

    output = (root / args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"release-manifest: wrote {output}")
    print(f"release-manifest: artifacts={len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
