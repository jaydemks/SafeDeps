from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

def cmd_doctor(args):
    root=Path(args.path).resolve()
    issues=[]
    warnings=[]
    safedeps_dir=root/".safedeps"
    policy_path=safedeps_dir/"policy.json"
    cache_path=safedeps_dir/"metadata-cache.json"

    if not safedeps_dir.exists():
        issues.append("Missing .safedeps directory. Run: safedeps init")
    if not policy_path.exists():
        issues.append("Missing .safedeps/policy.json. Run: safedeps init")
    else:
        try:
            json.loads(policy_path.read_text(encoding="utf-8"))
        except Exception as e:
            issues.append(f"Invalid policy JSON: {e}")

    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
            if not isinstance(cache, dict):
                issues.append("metadata-cache.json must be a JSON object.")
        except Exception as e:
            issues.append(f"Invalid metadata cache JSON: {e}")
    else:
        warnings.append("No metadata cache found (.safedeps/metadata-cache.json). Age/churn signals will be inactive unless cache is provided.")
    warnings.extend(_python_env_warnings())

    print("\nSafeDeps doctor")
    print(f"Path: {root}")
    if issues:
        print("Status: FAIL")
        for i in issues:
            print(f"- ISSUE: {i}")
    else:
        print("Status: PASS")
    for w in warnings:
        print(f"- WARNING: {w}")
    return 2 if issues else 0

def _python_env_warnings():
    warnings = []
    if sys.version_info < (3, 10):
        warnings.append("Python <3.10 detected. SafeDeps requires Python 3.10+.")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "--version"],
            text=True,
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            warnings.append("pytest is not available in this environment. Install dev deps with: pip install .[dev]")
    except Exception:
        warnings.append("pytest check unavailable. Ensure dev deps are installed with: pip install .[dev]")
    return warnings

