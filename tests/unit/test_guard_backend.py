import os
import stat

from safedeps.guard_backend import GuardBackendFiles, write_guard_backend_files


def _files() -> GuardBackendFiles:
    return GuardBackendFiles(
        pip_wrapper="#!/usr/bin/env bash\npip-wrapper\n",
        pip_ps1="pip ps1",
        pip3_ps1="pip3 ps1",
        pip_cmd="pip cmd",
        npm_wrapper="#!/usr/bin/env bash\nnpm-wrapper\n",
        npm_ps1="npm ps1",
        npm_cmd="npm cmd",
        python_wrapper="#!/usr/bin/env bash\npython-wrapper\n",
        python_ps1="python ps1",
        python_cmd="python cmd",
        activate_ps1="activate ps1",
    )


def _is_executable(path):
    if os.name == "nt":
        return path.exists()
    return bool(path.stat().st_mode & stat.S_IXUSR)


def test_write_guard_backend_files_installs_posix_and_windows_wrappers(tmp_path):
    bindir = tmp_path / ".safedeps" / "bin"
    install = write_guard_backend_files(tmp_path, bindir, bindir, _files(), windows=False)

    assert install.pip_path == bindir / "pip"
    assert install.pip3_path == bindir / "pip3"
    assert (bindir / "pip").read_text(encoding="utf-8") == "#!/usr/bin/env bash\npip-wrapper\n"
    assert (bindir / "pip3").read_text(encoding="utf-8") == "#!/usr/bin/env bash\npip-wrapper\n"
    assert (bindir / "pip.ps1").read_text(encoding="utf-8") == "pip ps1"
    assert (bindir / "pip3.ps1").read_text(encoding="utf-8") == "pip3 ps1"
    assert (bindir / "pip.cmd").read_text(encoding="utf-8") == "pip cmd"
    assert (bindir / "pip3.cmd").read_text(encoding="utf-8") == "pip cmd"
    assert (bindir / "npm").read_text(encoding="utf-8") == "#!/usr/bin/env bash\nnpm-wrapper\n"
    assert (bindir / "python").read_text(encoding="utf-8") == "#!/usr/bin/env bash\npython-wrapper\n"
    assert (bindir / "python3").read_text(encoding="utf-8") == "#!/usr/bin/env bash\npython-wrapper\n"
    assert (bindir / "activate.ps1").exists() is False
    assert install.activate_ps1.read_text(encoding="utf-8") == "activate ps1"

    assert _is_executable(bindir / "pip")
    assert _is_executable(bindir / "pip3")
    assert _is_executable(bindir / "npm")
    assert _is_executable(bindir / "python")
    assert _is_executable(bindir / "python3")
    assert _is_executable(install.activate)
    assert '$PWD/.safedeps/bin:$PATH' in install.activate.read_text(encoding="utf-8")
    assert "SafeDeps pip guard active for this CMD session." in install.activate_bat.read_text(
        encoding="utf-8"
    )


def test_write_guard_backend_files_uses_windows_posix_bin_for_activation(tmp_path):
    bindir = tmp_path / ".safedeps" / "bin"
    posix_bindir = tmp_path / ".safedeps" / "bin-posix"

    install = write_guard_backend_files(tmp_path, bindir, posix_bindir, _files(), windows=True)

    assert install.pip_path == posix_bindir / "pip"
    assert install.pip3_path == posix_bindir / "pip3"
    assert (posix_bindir / "pip").exists()
    assert (bindir / "pip.cmd").exists()
    assert '$PWD/.safedeps/bin-posix:$PATH' in install.activate.read_text(encoding="utf-8")
