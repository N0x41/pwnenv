from __future__ import annotations

from pathlib import Path
import pwnlib


def load_pipeline():
    import importlib.util
    file = Path(__file__).resolve().parents[1] / "tools" / "pwnapi.py"
    spec = importlib.util.spec_from_file_location("pwnapi_mod", str(file))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


def test_choose_mode_flags(monkeypatch):
    mod = load_pipeline()
    pl = mod.Pipeline()
    # Simulate various args flags
    monkeypatch.setattr(mod.args, "GDB", True, raising=False)
    assert pl.choose_mode() in ("DEBUG", "REMOTE")  # depends on has_remote
    monkeypatch.setattr(mod.args, "GDB", False, raising=False)
    monkeypatch.setattr(mod.args, "DEBUG", True, raising=False)
    assert pl.choose_mode() == "DEBUG"
    monkeypatch.setattr(mod.args, "DEBUG", False, raising=False)
    monkeypatch.setattr(mod.args, "REMOTE", True, raising=False)
    assert pl.choose_mode() == "REMOTE"
    monkeypatch.setattr(mod.args, "REMOTE", False, raising=False)
    monkeypatch.setattr(mod.args, "LOCAL", True, raising=False)
    assert pl.choose_mode() == "LOCAL"


def test_connect_local_requires_binary(monkeypatch, tmp_path):
    mod = load_pipeline()
    pl = mod.Pipeline()
    pl.binary_path = None
    try:
        pl.connect("LOCAL")
        assert False, "Expected PwnlibException when binary_path missing"
    except pwnlib.exception.PwnlibException:
        pass


def test_connect_debug_uses_gdb(monkeypatch, tmp_path):
    mod = load_pipeline()
    pl = mod.Pipeline()
    # Provide a fake binary path
    fake_bin = tmp_path / "app"
    fake_bin.write_text("x")
    pl.binary_path = str(fake_bin)
    called = {}
    def fake_gdb_debug(path, gdbscript=None):
        called["path"], called["gdbscript"] = path, gdbscript
        class Dummy:
            def connected(self): return False
        return Dummy()
    monkeypatch.setattr(mod.gdb, "debug", fake_gdb_debug)
    pl.connect("DEBUG", gdbscript="continue")
    assert called["path"] == str(fake_bin)


def test_connect_remote_via_ssh(monkeypatch):
    mod = load_pipeline()
    pl = mod.Pipeline()
    pl.remote_host = "h"
    pl.remote_user = "u"
    pl.remote_path = "/bin/x"
    pl.remote_port = 22
    pl.has_remote = True  # since it's computed at __init__, update explicitly
    called = {}
    class DummyTube:
        def connected(self): return False
        def close(self): pass
    class DummySSH:
        def __call__(self, **kw):
            called["ssh"] = kw
            return self
        def process(self, cmd):
            called["cmd"] = cmd
            return DummyTube()
    monkeypatch.setattr(mod, "ssh", DummySSH())
    pl.connect("REMOTE")
    assert called["ssh"]["host"] == "h"
    assert called["ssh"]["user"] == "u"
    assert called["cmd"] == ["/bin/x"]
