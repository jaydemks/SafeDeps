from __future__ import annotations

from pathlib import Path

from safedeps.models import Finding


class Scanner:
    manager = "generic"

    def scan(self, root: Path, policy) -> tuple[list[Finding], list[dict]]:
        return [], []


def severity_for_exception(policy, manager, pkg, rule, default="HIGH"):
    return "INFO" if policy.has_exception(manager, pkg, rule) else default
