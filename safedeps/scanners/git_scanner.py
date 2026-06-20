from __future__ import annotations

import re
from pathlib import Path

from safedeps.models import Finding
from safedeps.scanners.base import Scanner


class GitScanner(Scanner):
    manager = "git"
    manifests = (".gitmodules",)
    lockfiles = ()
    supports_runtime_guard = False

    def scan(self, root: Path, policy):
        findings: list[Finding] = []
        components: list[dict] = []
        gm = root / ".gitmodules"
        if gm.exists():
            text = gm.read_text(errors="ignore")
            for url in re.findall(r"url\s*=\s*(.+)", text):
                clean = url.strip()
                components.append({"type": "git-submodule", "manager": "git", "name": clean, "version": ""})
                if clean.startswith("http://"):
                    findings.append(
                        Finding(
                            "CRITICAL",
                            "git",
                            "INSECURE_GIT_URL",
                            f"Insecure git submodule URL: {clean}",
                            ".gitmodules",
                            fix="Use HTTPS or SSH and pin submodule commit.",
                        )
                    )
        return findings, components
