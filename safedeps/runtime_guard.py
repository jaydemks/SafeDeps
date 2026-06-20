from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path


GUARDED_PIP_COMMANDS = {"install", "uninstall", "download"}


def _norm_path(value: str | os.PathLike[str]) -> str:
    return str(value).replace("\\", "/").rstrip("/").lower()


def _load_state(root: Path) -> dict:
    path = root / ".safedeps" / "guard-state.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _is_subpath(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def _pip_subcommand(argv: list[str]) -> str | None:
    if not argv:
        return None
    exe_name = Path(argv[0]).name.lower()
    if exe_name.startswith("pip") and len(argv) >= 2:
        return argv[1].lower()
    if argv[0] == "-m" and len(argv) >= 2 and argv[1].lower() in GUARDED_PIP_COMMANDS:
        return argv[1].lower()
    return None


def _package_tokens(args: list[str]) -> list[str]:
    tokens: list[str] = []
    expect_value = False
    value_options = {
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-i",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "-f",
    }
    value_option_prefixes = tuple(f"{option}=" for option in value_options if option.startswith("--"))
    for token in args:
        if expect_value:
            expect_value = False
            continue
        low = token.lower()
        if low.startswith(value_option_prefixes):
            continue
        if low in value_options:
            expect_value = True
            continue
        if token.startswith("-"):
            continue
        tokens.append(token)
    return tokens


def _option_values(args: list[str], options: set[str]) -> list[str]:
    values: list[str] = []
    expect_value = False
    for token in args:
        low = token.lower()
        if expect_value:
            values.append(token)
            expect_value = False
            continue
        if low in options:
            expect_value = True
            continue
        for option in options:
            if option.startswith("--") and low.startswith(f"{option}="):
                values.append(token.split("=", 1)[1])
                break
    return values


def _looks_like_local_reference(token: str) -> bool:
    low = token.lower()
    if token.startswith((".", "/", "\\")):
        return True
    if len(token) >= 3 and token[1] == ":" and token[2] in ("\\", "/"):
        return True
    return low.endswith((".whl", ".tar.gz", ".zip")) and not low.startswith(("http://", "https://"))


def _looks_like_direct_reference(token: str) -> bool:
    low = token.lower()
    if " @ " in low:
        _, reference = low.split(" @ ", 1)
        return reference.startswith(("git+", "http://", "https://", "file://"))
    return low.startswith(("git+", "http://", "https://", "file://"))


def _looks_like_local_or_direct_reference(token: str) -> bool:
    return _looks_like_local_reference(token) or _looks_like_direct_reference(token)


def _strip_requirement_line(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return []
    try:
        return shlex.split(stripped, comments=True, posix=True)
    except ValueError:
        return [stripped]


def _requirement_file_tokens(root: Path, args: list[str]) -> list[str]:
    tokens: list[str] = []
    seen: set[Path] = set()

    def read_file(raw_path: str) -> None:
        path = Path(raw_path)
        if not path.is_absolute():
            path = root / path
        try:
            resolved = path.resolve()
        except Exception:
            return
        if resolved in seen:
            return
        seen.add(resolved)
        try:
            lines = resolved.read_text(encoding="utf-8").splitlines()
        except Exception:
            return
        nested_args: list[str] = []
        for line in lines:
            parts = _strip_requirement_line(line)
            if not parts:
                continue
            nested_args.extend(parts)
            tokens.extend(_package_tokens(parts))
        for nested in _option_values(nested_args, {"-r", "--requirement", "-c", "--constraint"}):
            read_file(nested)

    for value in _option_values(args, {"-r", "--requirement", "-c", "--constraint"}):
        read_file(value)
    return tokens


def _package_name(token: str) -> str:
    raw = token.strip()
    if " @ " in raw:
        raw = raw.split(" @ ", 1)[0]
    raw = re.split(r"\s*(?:===|==|~=|!=|<=|>=|<|>)\s*", raw, maxsplit=1)[0]
    raw = raw.split("[", 1)[0]
    return raw.strip().lower().replace("_", "-")


def _contains_safedeps(args: list[str]) -> bool:
    return any(_package_name(token) == "safedeps" for token in _package_tokens(args))


def _block(message: str) -> None:
    sys.stderr.write(f"{message}\n")
    sys.stderr.flush()
    os._exit(2)


def _guard_applies(root: Path, expected_venv: str, state: dict) -> bool:
    if not bool(state.get("auto_guard", state.get("auto_guard_powershell", False))):
        return False
    scope = str(state.get("protection_scope") or "project").lower()
    project_root = Path(str(state.get("project_root") or root)).resolve()
    if scope != "global" and not _is_subpath(Path.cwd(), project_root):
        return False
    if scope != "global" and expected_venv:
        if _norm_path(sys.prefix) != _norm_path(expected_venv):
            return False
    return True


def _cleanup_before_self_uninstall(root: Path) -> None:
    try:
        from safedeps.guard import cleanup_guard_install

        cleanup_guard_install(root, remove_project_artifacts=False, disable_auto_guard=True)
    except Exception:
        pass


def _run_scan_or_block(fail_on: str = "HIGH") -> None:
    try:
        from safedeps.cli import main

        old_argv = sys.argv[:]
        try:
            code = main(["scan", ".", "--fail-on", fail_on])
        finally:
            sys.argv = old_argv
    except SystemExit as exc:
        code = int(exc.code or 0)
    except Exception as exc:
        _block(f"SafeDeps runtime guard scan failed: {exc}")
    if code:
        _block("SafeDeps blocked pip due to policy/security findings.")


def run(project_root: str, expected_venv: str = "", official_repo: str = "") -> None:
    if os.environ.get("SAFEDEPS_RUNTIME_GUARD_BYPASS") == "1":
        return

    argv = sys.argv[:]
    subcommand = _pip_subcommand(argv)
    if subcommand not in GUARDED_PIP_COMMANDS:
        return

    root = Path(project_root).resolve()
    state = _load_state(root)
    if not _guard_applies(root, expected_venv, state):
        return

    if argv[0] == "-m":
        pip_args = argv[1:]
    else:
        pip_args = argv[1:]
    package_args = pip_args[1:] if pip_args else []

    if subcommand == "uninstall":
        if _contains_safedeps(package_args):
            _cleanup_before_self_uninstall(root)
            return
        _block("Blocked: python runtime pip uninstall is disabled while SafeDeps guard is active.")

    if subcommand == "install":
        for token in [*_package_tokens(package_args), *_requirement_file_tokens(root, package_args)]:
            if _looks_like_local_reference(token):
                continue
            if _package_name(token) == "safedeps":
                continue
            if _looks_like_direct_reference(token):
                _block("Blocked: direct URL/VCS runtime install is not allowed without explicit review.")
            if "==" not in token:
                _block("Blocked: unpinned runtime install is not allowed. Use exact versions (example: package==1.2.3).")

    if subcommand in {"install", "download"} and _contains_safedeps(package_args):
        joined = " ".join(package_args)
        if not official_repo or official_repo.lower() not in joined.lower():
            _block("Blocked: SafeDeps updates are allowed only from official Git source.")

    fail_on = str(state.get("fail_on") or "HIGH").upper()
    _run_scan_or_block(fail_on)
