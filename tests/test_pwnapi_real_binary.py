from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
import pwd
import pytest


def load_pipeline():
    import importlib.util
    file = Path(__file__).resolve().parents[1] / "tools" / "pwnapi.py"
    spec = importlib.util.spec_from_file_location("pwnapi_mod", str(file))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


def compile_dummy(tmp_path: Path) -> Path:
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available; skipping real-binary test")
    c_src = tmp_path / "dummy.c"
    # Minimal program that exits immediately
    c_src.write_text(
        """
        #include <stdio.h>
        int main(void){
            /* Minimal program */
            return 0;
        }
        """
    )
    out = tmp_path / "dummy"
    # Build a simple non-PIE when possible; ignore flags if unsupported
    cmd = [
        "gcc",
        str(c_src),
        "-o",
        str(out),
    ]
    # Try to keep it simple; on systems with default PIE, it's fine
    subprocess.run(cmd, check=True)
    assert out.exists()
    return out


def ssh_localhost_available() -> bool:
    # Quick probe without prompting for password
    try:
        res = subprocess.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=2",
                "localhost",
                "true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return res.returncode == 0
    except FileNotFoundError:
        return False


def test_local_connect_with_real_binary(tmp_path):
    mod = load_pipeline()
    bin_path = compile_dummy(tmp_path)
    pl = mod.Pipeline()
    pl.binary_path = str(bin_path)
    # Use real process; close quickly if connected
    tube = pl.connect("LOCAL")
    try:
        if hasattr(tube, "connected") and tube.connected():
            tube.close()
    finally:
        # ensure any ssh session would be closed (not used here)
        if getattr(pl, "_ssh_session", None):
            pl._ssh_session.close()


def test_debug_with_real_binary_uses_gdb_stub(monkeypatch, tmp_path):
    mod = load_pipeline()
    bin_path = compile_dummy(tmp_path)
    pl = mod.Pipeline()
    pl.binary_path = str(bin_path)
    called = {}

    def fake_gdb_debug(path, gdbscript=None):
        called["path"] = path
        class Dummy:
            def connected(self):
                return False
        return Dummy()

    monkeypatch.setattr(mod.gdb, "debug", fake_gdb_debug)
    pl.connect("DEBUG")
    assert called["path"] == str(bin_path)


@pytest.mark.skipif(not ssh_localhost_available(), reason="localhost ssh not available/passwordless")
def test_remote_localhost_with_real_binary(tmp_path):
    mod = load_pipeline()
    bin_path = compile_dummy(tmp_path)
    pl = mod.Pipeline()
    # Configure remote as localhost with current user and local binary path
    user = pwd.getpwuid(os.getuid()).pw_name
    pl.remote_host = "localhost"
    pl.remote_user = user
    pl.remote_port = 22
    pl.remote_path = str(bin_path)
    pl.has_remote = True
    # Attempt to run the binary remotely; it should exit immediately
    tube = pl.connect("REMOTE")
    try:
        if hasattr(tube, "connected") and tube.connected():
            tube.close()
    finally:
        if getattr(pl, "_ssh_session", None):
            pl._ssh_session.close()
