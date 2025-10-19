from __future__ import annotations

from pathlib import Path
import json
import types


def load_cli_module():
    cli_path = Path(__file__).resolve().parents[1] / "pwnenv"
    code = cli_path.read_text()
    module = types.ModuleType("pwnenv_cli")
    module.__file__ = str(cli_path)
    compiled = compile(code, str(cli_path), "exec")
    exec(compiled, module.__dict__)
    return module


def test_load_config_invalid_json(monkeypatch, tmp_path):
    mod = load_cli_module()
    conf_path = tmp_path / ".local" / "share" / "pwnenv.json"
    monkeypatch.setattr(mod, "CONFIG_PATH", conf_path)
    conf_path.parent.mkdir(parents=True, exist_ok=True)
    conf_path.write_text("{ not json")
    data = mod.load_config()
    # Should fall back to defaults
    assert data["challenges_dir"]


def test_handle_init_libc_is_directory_errors(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    libc_dir = tmp_path / "libdir"
    libc_dir.mkdir()

    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(Exception("no pwn")))

    ns = types.SimpleNamespace(
        project_name="ProjLibDir",
        source_path=None,
        local=None,
        ssh=None,
        ssh_host=None,
        ssh_user=None,
        ssh_port=None,
        ssh_pass=None,
        ssh_bin=None,
        ssh_src=None,
        libc=str(libc_dir),
        source_path_option=None,
    )

    try:
        mod.handle_init(ns, paths)
        assert False, "Expected SystemExit when --libc points to a directory"
    except SystemExit:
        pass


def test_handle_init_ssh_without_user(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)

    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(Exception("no pwn")))

    ns = types.SimpleNamespace(
        project_name="OnlyHost",
        source_path=None,
        local=None,
        ssh="example.com:/opt/bin/chal",
        ssh_host=None,
        ssh_user=None,
        ssh_port=None,
        ssh_pass=None,
        ssh_bin=None,
        ssh_src=None,
        libc=None,
        source_path_option=None,
    )

    mod.handle_init(ns, paths)
    conf = json.loads((paths.challenges_dir / "OnlyHost" / "pwnenv.conf.json").read_text())
    assert conf["ssh"]["host"] == "example.com"
    assert conf["ssh"]["bin"] == "/opt/bin/chal"
    assert "user" not in conf["ssh"]


def test_exec_shell_tmux_without_config_uses_default_tmux(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    project = paths.challenges_dir / "Pnc"
    project.mkdir(parents=True)

    # Ensure there is no tmux config anywhere
    paths.tmux_config = tmp_path / "does_not_exist.tmux"
    paths.tmux_default_config = tmp_path / "absent.tmux"

    called = {}

    def fake_which(bin_name):
        return "/usr/bin/tmux"

    def fake_execve(file, args, env):
        called["file"], called["args"] = file, args
        raise SystemExit(0)

    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.setenv("SHELL", "/bin/sh")
    monkeypatch.setattr(mod.shutil, "which", fake_which)
    monkeypatch.setattr(mod.os, "execve", fake_execve)

    try:
        mod.exec_shell(project, paths, "Name")
    except SystemExit:
        pass

    assert called.get("file") == "/usr/bin/tmux"
    args = called.get("args")
    assert args and args[0] == "/usr/bin/tmux"
    # No -f flag when there is no tmux config
    assert "-f" not in args