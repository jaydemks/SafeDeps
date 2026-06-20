from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GuardBackendFiles:
    pip_wrapper: str
    pip_ps1: str
    pip3_ps1: str
    pip_cmd: str
    npm_wrapper: str
    npm_ps1: str
    npm_cmd: str
    python_wrapper: str
    python_ps1: str
    python_cmd: str
    activate_ps1: str


@dataclass(frozen=True)
class GuardBackendInstall:
    pip_path: Path
    pip3_path: Path
    activate: Path
    activate_bat: Path
    activate_ps1: Path


def write_guard_backend_files(
    root: Path,
    bindir: Path,
    posix_bindir: Path,
    files: GuardBackendFiles,
    *,
    windows: bool,
) -> GuardBackendInstall:
    bindir.mkdir(parents=True, exist_ok=True)
    posix_bindir.mkdir(parents=True, exist_ok=True)

    pip_path = posix_bindir / "pip"
    pip3_path = posix_bindir / "pip3"
    pip_path.write_text(files.pip_wrapper, encoding="utf-8", newline="\n")
    pip3_path.write_text(files.pip_wrapper, encoding="utf-8", newline="\n")
    pip_path.chmod(0o755)
    pip3_path.chmod(0o755)

    (bindir / "pip.ps1").write_text(files.pip_ps1, encoding="utf-8")
    (bindir / "pip3.ps1").write_text(files.pip3_ps1, encoding="utf-8")
    (bindir / "pip.cmd").write_text(files.pip_cmd, encoding="utf-8")
    (bindir / "pip3.cmd").write_text(files.pip_cmd, encoding="utf-8")

    npm_path = posix_bindir / "npm"
    npm_path.write_text(files.npm_wrapper, encoding="utf-8", newline="\n")
    npm_path.chmod(0o755)
    (bindir / "npm.ps1").write_text(files.npm_ps1, encoding="utf-8")
    (bindir / "npm.cmd").write_text(files.npm_cmd, encoding="utf-8")

    python_path = posix_bindir / "python"
    python3_path = posix_bindir / "python3"
    python_path.write_text(files.python_wrapper, encoding="utf-8", newline="\n")
    python3_path.write_text(files.python_wrapper, encoding="utf-8", newline="\n")
    python_path.chmod(0o755)
    python3_path.chmod(0o755)
    (bindir / "python.ps1").write_text(files.python_ps1, encoding="utf-8")
    (bindir / "python3.ps1").write_text(files.python_ps1, encoding="utf-8")
    (bindir / "python.cmd").write_text(files.python_cmd, encoding="utf-8")
    (bindir / "python3.cmd").write_text(files.python_cmd, encoding="utf-8")

    activate = root / ".safedeps" / "activate.sh"
    activate_path = "$PWD/.safedeps/bin-posix" if windows else "$PWD/.safedeps/bin"
    activate.write_text(
        "#!/usr/bin/env bash\n"
        f'export PATH="{activate_path}:$PATH"\n'
        'echo "SafeDeps pip guard active for this shell."\n',
        encoding="utf-8",
        newline="\n",
    )
    activate.chmod(0o755)

    activate_bat = root / ".safedeps" / "activate.bat"
    activate_bat.write_text(
        "@echo off\r\n"
        "set \"safeDepsBin=%~dp0bin\"\r\n"
        "set \"PATH=%safeDepsBin%;%PATH%\"\r\n"
        "echo SafeDeps pip guard active for this CMD session.\r\n",
        encoding="utf-8",
    )

    activate_ps1 = root / ".safedeps" / "activate.ps1"
    activate_ps1.write_text(files.activate_ps1, encoding="utf-8")

    return GuardBackendInstall(
        pip_path=pip_path,
        pip3_path=pip3_path,
        activate=activate,
        activate_bat=activate_bat,
        activate_ps1=activate_ps1,
    )
