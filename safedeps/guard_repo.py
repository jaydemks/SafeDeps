from __future__ import annotations

import subprocess
from pathlib import Path

def detect_official_repo_url(root: Path):
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return ""
        return (proc.stdout or "").strip()
    except Exception:
        return ""
