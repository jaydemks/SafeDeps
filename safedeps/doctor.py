from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from .guard_state import get_current_shell_guard_status, get_guard_mode_status, get_setup_status
from .policy import validate_policy_schema_v1


_KNOWN_MANIFESTS = {
    "pip": ("requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock", "uv.lock"),
    "npm": ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
    "nuget": ("Directory.Packages.props", "packages.config", "packages.lock.json", "NuGet.Config", "nuget.config"),
}


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
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            _validate_policy_shape(policy, issues, warnings)
        except Exception as e:
            issues.append(f"Invalid policy JSON: {e}")

    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
            if not isinstance(cache, dict):
                issues.append("metadata-cache.json must be a JSON object.")
            else:
                warnings.extend(_metadata_cache_warnings(cache))
        except Exception as e:
            issues.append(f"Invalid metadata cache JSON: {e}")
    else:
        warnings.append("No metadata cache found (.safedeps/metadata-cache.json). Age/churn signals will be inactive unless cache is provided.")
    warnings.extend(_project_health_warnings(root))
    warnings.extend(_guard_health_warnings(root))
    warnings.extend(_toolchain_warnings(root))
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

def _validate_policy_shape(policy: object, issues: list[str], warnings: list[str]):
    policy_issues = validate_policy_schema_v1(policy)
    issues.extend(policy_issues)
    if not isinstance(policy, dict):
        return
    if "schema" not in policy:
        warnings.append("policy.json has no schema field; consider regenerating with: safedeps init --force")
    if policy.get("require_lockfiles") is False:
        warnings.append("Policy does not require lockfiles. This weakens reproducibility checks.")

def _metadata_cache_warnings(cache: dict):
    warnings = []
    for manager, packages in cache.items():
        if not isinstance(packages, dict):
            warnings.append(f"metadata-cache.json entry for {manager!s} should be an object of package metadata.")
            continue
        for package, metadata in packages.items():
            if not isinstance(metadata, dict):
                warnings.append(f"metadata-cache.json entry {manager!s}/{package!s} should be an object.")
                continue
            published = str(metadata.get("published", "")).strip()
            if published:
                try:
                    from datetime import datetime

                    datetime.fromisoformat(published)
                except Exception:
                    warnings.append(f"metadata-cache.json entry {manager!s}/{package!s} has invalid published date.")
    return warnings

def _project_health_warnings(root: Path):
    warnings = []
    detected = {
        manager
        for manager, names in _KNOWN_MANIFESTS.items()
        if any((root / name).exists() for name in names) or (manager == "nuget" and any(root.glob("*.csproj")))
    }
    if not detected:
        warnings.append("No known dependency manifest detected at this path.")
        return warnings
    if "pip" in detected:
        if (root / "requirements.txt").exists() and not (root / "requirements.lock").exists():
            warnings.append("Python requirements.txt found without requirements.lock.")
        if (root / "pyproject.toml").exists() and not any((root / name).exists() for name in ("uv.lock", "poetry.lock", "requirements.lock")):
            warnings.append("pyproject.toml found without uv.lock, poetry.lock, or requirements.lock.")
    if "npm" in detected and not any((root / name).exists() for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")):
        warnings.append("package.json found without npm/pnpm/yarn lockfile.")
    if "nuget" in detected and not (root / "packages.lock.json").exists():
        warnings.append(".NET project metadata found without packages.lock.json.")
    return warnings

def _guard_health_warnings(root: Path):
    warnings = []
    try:
        setup = get_setup_status(root)
        if str(setup).startswith("Not configured"):
            warnings.append(f"Guard setup incomplete: {setup}")
    except Exception as e:
        warnings.append(f"Guard setup status unavailable: {e}")
    if not (root / ".safedeps").exists():
        return warnings
    try:
        shell_status = get_current_shell_guard_status(root)
        if "INACTIVE" in str(shell_status).upper():
            warnings.append(f"Current shell guard inactive: {shell_status}")
    except Exception as e:
        warnings.append(f"Current shell guard status unavailable: {e}")
    try:
        mode_status = get_guard_mode_status(root)
        if "OFF" in str(mode_status).upper():
            warnings.append(f"Auto guard inactive: {mode_status}")
    except Exception as e:
        warnings.append(f"Guard mode status unavailable: {e}")
    return warnings

def _toolchain_warnings(root: Path):
    warnings = []
    has_npm_project = (root / "package.json").exists()
    has_dotnet_project = any(root.glob("*.csproj")) or (root / "Directory.Packages.props").exists()
    if has_npm_project and shutil.which("npm") is None:
        warnings.append("npm project detected but npm is not available on PATH.")
    if has_dotnet_project and shutil.which("dotnet") is None:
        warnings.append(".NET project detected but dotnet is not available on PATH.")
    return warnings

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
