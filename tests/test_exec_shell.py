from __future__ import annotations

from pathlib import Path
import types


def load_cli_module():
    cli_path = Path(__file__).resolve().parents[1] / "pwnenv"
    code = cli_path.read_text()
    module = types.ModuleType("pwnenv_cli")
    module.__file__ = str(cli_path)
    compiled = compile(code, str(cli_path), "exec")
    exec(compiled, module.__dict__)
    return module


def test_exec_shell_inside_tmux_calls_shell(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    project = paths.challenges_dir / "P"
    project.mkdir(parents=True)

    called = {}

    def fake_execve(file, args, env):
        called["file"] = file
        called["args"] = args
        called["env"] = env
        raise SystemExit(0)  # stop here safely

    monkeypatch.setenv("TMUX", "1")
    monkeypatch.setenv("SHELL", "/bin/sh")
    monkeypatch.setattr(mod.os, "execve", fake_execve)

    try:
        mod.exec_shell(project, paths, "P")
    except SystemExit:
        pass

    assert called.get("file") == "/bin/sh"
    assert called.get("args") == ["/bin/sh"]
    env = called.get("env")
    assert env and env.get("VIRTUAL_ENV") == str(paths.venv_dir)
    assert env.get("PWD") == str(project)
    assert str(paths.tools_dir) in env.get("PYTHONPATH", "")


def test_exec_shell_with_tmux_config(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    project = paths.challenges_dir / "P2"
    project.mkdir(parents=True)

    tmux_cfg = tmp_path / "my.tmux"
    tmux_cfg.write_text("set -g mouse on\n")
    monkeypatch.setenv("PWNENV_TMUX_CONFIG", str(tmux_cfg))

    called = {}

    def fake_which(bin_name):
        assert bin_name == "tmux"
        return "/usr/bin/tmux"

    def fake_execve(file, args, env):
        called["file"] = file
        called["args"] = args
        called["env"] = env
        raise SystemExit(0)

    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.setenv("SHELL", "/bin/sh")
    monkeypatch.setattr(mod.shutil, "which", fake_which)
    monkeypatch.setattr(mod.os, "execve", fake_execve)

    try:
        mod.exec_shell(project, paths, "My Proj")
    except SystemExit:
        pass

    assert called.get("file") == "/usr/bin/tmux"
    args = called.get("args")
    assert args and args[0] == "/usr/bin/tmux"
    assert "-f" in args and str(tmux_cfg) in args
    # Ensure session name uses underscores for spaces
    assert "new-session" in args and "-As" in args and "My_Proj" in args
    # Working dir and shell
    assert "-c" in args and str(project) in args
    assert args[-1] == "/bin/sh"


def test_exec_shell_tmux_existing_session_sources_config(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    project = paths.challenges_dir / "P4"
    project.mkdir(parents=True)

    tmux_cfg = tmp_path / "conf.tmux"
    tmux_cfg.write_text("set -g mouse on\n")
    monkeypatch.setenv("PWNENV_TMUX_CONFIG", str(tmux_cfg))

    # Fake tmux binary
    monkeypatch.setattr(mod.shutil, "which", lambda *_: "/usr/bin/tmux")

    calls = []
    def fake_run(argv, **kw):
        calls.append(list(argv))
        class R:
            def __init__(self, rc):
                self.returncode = rc
        # First call: 'has-session -t <name>' -> returncode 0 (exists)
        if calls and calls[0][1:3] == ["has-session", "-t"]:
            return R(0)
        return R(1)

    def fake_execve(file, args, env):
        # Should be final 'tmux -f <cfg> new-session -As <name> -c <dir> <shell>'
        raise SystemExit(0)

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setenv("SHELL", "/bin/sh")
    monkeypatch.setattr(mod.os, "execve", fake_execve)
    try:
        mod.exec_shell(project, paths, "Name")
    except SystemExit:
        pass
    # We expect at least two subprocess.run calls: has-session and source-file
    assert any(cmd[:2] == ["/usr/bin/tmux", "has-session"] for cmd in calls)
    assert any(cmd[:2] == ["/usr/bin/tmux", "source-file"] for cmd in calls)


def test_exec_shell_without_tmux_falls_back_to_shell(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    project = paths.challenges_dir / "P3"
    project.mkdir(parents=True)

    # No tmux on system
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.setenv("SHELL", "/bin/bash")
    monkeypatch.setattr(mod.shutil, "which", lambda *_: None)

    called = {}
    def fake_execve(file, args, env):
        called["file"], called["args"], called["env"] = file, args, env
        raise SystemExit(0)

    monkeypatch.setattr(mod.os, "execve", fake_execve)
    try:
        mod.exec_shell(project, paths, None)
    except SystemExit:
        pass
    assert called.get("file") == "/bin/bash"
    assert called.get("args") == ["/bin/bash"]