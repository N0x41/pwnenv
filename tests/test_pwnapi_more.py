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


def test_debug_requires_binary_error(monkeypatch):
    mod = load_pipeline()
    pl = mod.Pipeline()
    pl.binary_path = None
    # Expect pwntools to raise on log.error
    try:
        pl.connect("DEBUG")
        assert False, "Expected PwnlibException when DEBUG without binary"
    except pwnlib.exception.PwnlibException:
        pass


def test_remote_requires_config_error(monkeypatch):
    mod = load_pipeline()
    pl = mod.Pipeline()
    # Ensure no remote configuration present
    pl.has_remote = False
    try:
        pl.connect("REMOTE")
        assert False, "Expected PwnlibException when REMOTE without ssh config"
    except pwnlib.exception.PwnlibException:
        pass


def test_remote_missing_target_path_error(monkeypatch):
    mod = load_pipeline()
    pl = mod.Pipeline()
    # Force inconsistent state to reach target_path error branch
    pl.remote_host = "h"
    pl.remote_user = "u"
    pl.remote_path = None
    pl.binary_path = None
    pl.has_remote = True  # force skip of early error

    class DummySSH:
        def __call__(self, **kw):
            return self
        def process(self, cmd):
            raise AssertionError("process should not be called due to error")

    monkeypatch.setattr(mod, "ssh", DummySSH())

    try:
        pl.connect("REMOTE")
        assert False, "Expected PwnlibException when no remote or local binary path"
    except pwnlib.exception.PwnlibException:
        pass


def test_local_uses_process(monkeypatch, tmp_path):
    mod = load_pipeline()
    pl = mod.Pipeline()
    fake_bin = tmp_path / "bin"
    fake_bin.write_text("x")
    pl.binary_path = str(fake_bin)
    called = {}

    class DummyTube:
        def connected(self):
            return False

    def fake_process(path):
        called["path"] = path
        return DummyTube()

    monkeypatch.setattr(mod, "process", fake_process)
    t = pl.connect("LOCAL")
    assert called["path"] == str(fake_bin)
    assert hasattr(t, "connected")


def test_choose_mode_gdb_remote_vs_debug(monkeypatch):
    mod = load_pipeline()
    pl = mod.Pipeline()
    # Case 1: has_remote only -> choose_mode returns REMOTE when GDB set
    pl.has_remote = True
    pl.has_local = False
    monkeypatch.setattr(mod.args, "GDB", True, raising=False)
    assert pl.choose_mode() == "REMOTE"

    # Case 2: both local+remote -> choose_mode returns DEBUG when GDB set
    pl.has_local = True
    assert pl.choose_mode() == "DEBUG"


def test_default_mode_remote_when_host_only():
    mod = load_pipeline()
    pl = mod.Pipeline()
    pl.has_remote = False
    pl.has_local = False
    pl.remote_host = "example.com"
    assert pl.default_mode == "REMOTE"


def test_run_executes_steps_and_cleans_up(monkeypatch):
    mod = load_pipeline()
    pl = mod.Pipeline()

    calls = {"steps": [], "interactive": 0, "close": 0, "ssh_close": 0}

    class DummyTube:
        def __init__(self):
            self._connected = True
        def connected(self):
            return self._connected
        def interactive(self):
            calls["interactive"] += 1
            # Simulate end of interaction disconnecting the tube
            self._connected = False
        def close(self):
            calls["close"] += 1

    def fake_connect(mode, breakpoint=None, gdbscript=None):
        # Ensure we can test the mode is propagated (but not essential)
        assert mode in ("LOCAL", "REMOTE", "DEBUG")
        return DummyTube()

    class DummySSH:
        def close(self):
            calls["ssh_close"] += 1

    # Wire the fakes
    monkeypatch.setattr(pl, "connect", fake_connect)
    pl._ssh_session = DummySSH()

    @pl.step
    def step1(_pl, _io):
        calls["steps"].append("step1")

    @pl.step
    def step2(_pl, _io):
        calls["steps"].append("step2")

    pl.run(mode="LOCAL")
    assert calls["steps"] == ["step1", "step2"]
    assert calls["interactive"] == 1
    # close is not called because interactive disconnected the tube
    assert calls["close"] == 0
    # ssh session should be closed in finally
    assert calls["ssh_close"] == 1


def test_gdb_breakpoint_included(monkeypatch, tmp_path):
    mod = load_pipeline()
    pl = mod.Pipeline()
    fake_bin = tmp_path / "app"
    fake_bin.write_text("x")
    pl.binary_path = str(fake_bin)
    captured = {}

    def fake_gdb_debug(path, gdbscript=None):
        captured["script"] = gdbscript or ""
        class Dummy:
            def connected(self):
                return False
        return Dummy()

    monkeypatch.setattr(mod.gdb, "debug", fake_gdb_debug)
    pl.connect("DEBUG", breakpoint=0x401000)
    assert "break *0x401000" in captured["script"]
    assert "continue" in captured["script"]


def test_remote_with_password_includes_password(monkeypatch):
    mod = load_pipeline()
    pl = mod.Pipeline()
    pl.remote_host = "h"
    pl.remote_user = "u"
    pl.remote_path = "/bin/x"
    pl.remote_port = 2222
    pl.remote_pass = "secret"
    pl.has_remote = True

    called = {"ssh": None, "cmd": None}

    class DummyTube:
        def connected(self):
            return False
        def close(self):
            pass

    class DummySSH:
        def __call__(self, **kw):
            called["ssh"] = kw
            return self
        def process(self, cmd):
            called["cmd"] = cmd
            return DummyTube()

    monkeypatch.setattr(mod, "ssh", DummySSH())
    pl.connect("REMOTE")
    assert called["ssh"]["password"] == "secret"
    assert called["ssh"]["port"] == 2222
    assert called["cmd"] == ["/bin/x"]


def test_debug_default_gdbscript_contains_pwndbg(monkeypatch, tmp_path):
    mod = load_pipeline()
    pl = mod.Pipeline()
    fake_bin = tmp_path / "dummy_file"
    fake_bin.write_text("x")
    pl.binary_path = str(fake_bin)
    captured = {}

    def fake_gdb_debug(path, gdbscript=None):
        captured["script"] = gdbscript or ""
        class Dummy:
            def connected(self):
                return False
        return Dummy()

    monkeypatch.setattr(mod.gdb, "debug", fake_gdb_debug)
    # Use a string breakpoint to exercise that branch and default pwndbg sourcing
    pl.connect("DEBUG", breakpoint="main")
    assert captured["script"].startswith("source /usr/share/pwndbg/gdbinit.py")
    assert "break main" in captured["script"]
    assert captured["script"].strip().endswith("continue")


def test_connect_forces_debug_when_gdb_flag_set(monkeypatch, tmp_path):
    mod = load_pipeline()
    pl = mod.Pipeline()
    fake_bin = tmp_path / "dummy_file"
    fake_bin.write_text("x")
    pl.binary_path = str(fake_bin)
    called = {"used_gdb": False}

    def fake_gdb_debug(path, gdbscript=None):
        called["used_gdb"] = True
        class Dummy:
            def connected(self):
                return False
        return Dummy()

    monkeypatch.setattr(mod.gdb, "debug", fake_gdb_debug)
    # Force GDB flag and request LOCAL; it should be converted to DEBUG
    monkeypatch.setattr(mod.args, "GDB", True, raising=False)
    pl.connect("LOCAL")
    assert called["used_gdb"] is True


def test_remote_gdb_over_ssh(monkeypatch):
    mod = load_pipeline()
    pl = mod.Pipeline()
    # Configure remote target
    pl.remote_host = "h"
    pl.remote_user = "u"
    pl.remote_port = 2222
    pl.remote_path = "/bin/x"
    pl.has_remote = True

    # Capture calls
    captured = {"ssh_kwargs": None, "gdb_cmd": None, "gdb_script": None, "gdb_ssh": None}

    class DummySSH:
        def __call__(self, **kw):
            captured["ssh_kwargs"] = kw
            return self
        def process(self, cmd):
            raise AssertionError("process() should not be used when GDB is set")

    class DummyTube:
        def connected(self):
            return False

    def fake_gdb_debug(command, gdbscript=None, ssh=None):
        captured["gdb_cmd"] = command
        captured["gdb_script"] = gdbscript
        captured["gdb_ssh"] = ssh
        return DummyTube()

    # Force GDB and wire stubs
    monkeypatch.setattr(mod.args, "GDB", True, raising=False)
    monkeypatch.setattr(mod, "ssh", DummySSH())
    monkeypatch.setattr(mod.gdb, "debug", fake_gdb_debug)

    # Provide a custom gdbscript to ensure it's forwarded
    pl.connect("REMOTE", gdbscript="si")

    assert captured["ssh_kwargs"]["host"] == "h"
    assert captured["ssh_kwargs"]["user"] == "u"
    assert captured["ssh_kwargs"]["port"] == 2222
    assert captured["gdb_cmd"] == ["/bin/x"]
    assert captured["gdb_script"] == "si"
    # The ssh session object passed to gdb.debug should be the DummySSH instance
    assert captured["gdb_ssh"] is not None
