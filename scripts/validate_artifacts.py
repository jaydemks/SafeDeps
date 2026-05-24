#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


REQUIRED_FILES = [
    "safedeps-report.json",
    "safedeps-sbom.json",
    "safedeps.sarif",
    "safedeps.cdx.json",
    "safedeps.spdx.json",
]


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Invalid JSON in {path.name}: {exc}") from exc


def validate(out_dir: Path) -> list[str]:
    errors: list[str] = []

    for rel in REQUIRED_FILES:
        path = out_dir / rel
        if not path.exists():
            errors.append(f"Missing required artifact: {path}")

    if errors:
        return errors

    report = _load_json(out_dir / "safedeps-report.json")
    if not isinstance(report, dict) or "findings" not in report or "ok" not in report:
        errors.append("safedeps-report.json missing required keys: ok/findings")

    sbom = _load_json(out_dir / "safedeps-sbom.json")
    if not isinstance(sbom, dict) or "components" not in sbom:
        errors.append("safedeps-sbom.json missing required key: components")

    sarif = _load_json(out_dir / "safedeps.sarif")
    if sarif.get("version") != "2.1.0" or not isinstance(sarif.get("runs"), list):
        errors.append("safedeps.sarif has invalid SARIF version/runs structure")

    cdx = _load_json(out_dir / "safedeps.cdx.json")
    if cdx.get("bomFormat") != "CycloneDX" or cdx.get("specVersion") != "1.5":
        errors.append("safedeps.cdx.json has invalid CycloneDX header")

    spdx = _load_json(out_dir / "safedeps.spdx.json")
    if spdx.get("spdxVersion") != "SPDX-2.3" or not isinstance(spdx.get("packages"), list):
        errors.append("safedeps.spdx.json has invalid SPDX header/packages")

    return errors


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    out_dir = Path(args[0] if args else "security-artifacts")
    errs = validate(out_dir)
    if errs:
        print("Artifact validation failed:")
        for err in errs:
            print(f"- {err}")
        return 2
    print(f"Artifact validation passed: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
