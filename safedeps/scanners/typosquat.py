from __future__ import annotations

from safedeps.models import Finding


def typosquat_finding(policy, manager: str, package: str, file_ref: str, max_distance: int = 1):
    if not package or not policy.data.get("enable_typosquat_detection", True):
        return None
    normalized = _normalize(package)
    protected = policy.data.get("protected_packages", [])
    for candidate in protected:
        cand_norm = _normalize(str(candidate))
        if not cand_norm or cand_norm == normalized:
            continue
        if abs(len(cand_norm) - len(normalized)) > max_distance:
            continue
        if _levenshtein(cand_norm, normalized) <= max_distance:
            return Finding(
                "MEDIUM",
                manager,
                "TYPOSQUATTING_RISK",
                f"Package '{package}' is very similar to protected package '{candidate}'.",
                file_ref,
                package,
                fix="Verify package spelling, publisher identity, and source before install.",
            )
    return None


def _normalize(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch.isalnum())


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            ins = cur[j - 1] + 1
            delete = prev[j] + 1
            repl = prev[j - 1] + (0 if ca == cb else 1)
            cur.append(min(ins, delete, repl))
        prev = cur
    return prev[-1]
