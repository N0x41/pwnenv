from __future__ import annotations

from pathlib import Path
import json
import types


def load_cli_module() -> types.ModuleType:
    cli_path = Path(__file__).resolve().parents[1] / "pwnenv"
    code = cli_path.read_text()
    module = types.ModuleType("pwnenv_cli")
    module.__file__ = str(cli_path)
    compiled = compile(code, str(cli_path), "exec")
    exec(compiled, module.__dict__)
    return module


def test_load_config_creates_and_updates(monkeypatch, tmp_path):
    mod = load_cli_module()
    conf_path = tmp_path / ".local" / "share" / "pwnenv.json"
    monkeypatch.setattr(mod, "CONFIG_PATH", conf_path)

    # First call should create file with defaults
    data = mod.load_config()
    assert conf_path.exists()
    assert "challenges_dir" in data

    # Write partial config missing a key, then ensure it is completed
    partial = {"custom": "x"}
    conf_path.write_text(json.dumps(partial))
    updated = mod.load_config()
    assert updated.get("challenges_dir") == data["challenges_dir"]
    saved = json.loads(conf_path.read_text())
    assert "challenges_dir" in saved


def test_expand_path_tilde_and_resolve():
    mod = load_cli_module()
    p = mod.expand_path("~")
    assert isinstance(p, Path)
    assert p.is_absolute()


def test_paths_initialization_env_tmux(monkeypatch, tmp_path):
    mod = load_cli_module()
    tmux_cfg = tmp_path / "my.tmux"
    tmux_cfg.write_text("set -g mouse on\n")
    monkeypatch.setenv("PWNENV_TMUX_CONFIG", str(tmux_cfg))
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    assert paths.tmux_config == tmux_cfg.resolve()
    assert paths.challenges_dir == (tmp_path / "challs").resolve()


def test_self_setup_copies_assets_and_skips_venv(monkeypatch, tmp_path):
    mod = load_cli_module()

    # Prepare fake source tools
    src = tmp_path / "src_tools"
    (src / "tmux-sidebar").mkdir(parents=True)
    (src / "pwnapi.py").write_text("# api\n")
    (src / "pwnenv.mako").write_text("## template\n")
    (src / "tmux.config").write_text("set -g mouse on\n")
    (src / "tmux-sidebar" / "sidebar.tmux").write_text("# sidebar\n")

    # Prepare paths and pre-create venv to force early return (skip venv creation)
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    # Override paths to operate inside tmp dirs
    paths.venv_dir = tmp_path / "challs" / ".pwnenv"
    paths.tools_dir = paths.venv_dir / "tools"
    paths.tools_dir.mkdir(parents=True, exist_ok=True)
    paths.api_script = paths.tools_dir / "pwnapi.py"
    paths.tmux_default_config = src / "tmux.config"

    # Create legacy file that should be removed
    legacy = paths.tools_dir / "pwnlib_api.py"
    legacy.write_text("legacy")

    # Ensure venv exists so self_setup returns early after copying
    paths.venv_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("PWNENV_TOOLS_PATH", str(src))
    mod.self_setup(paths)

    # Assets copied into venv tools dir
    assert (paths.tools_dir / "pwnapi.py").exists()
    assert (paths.tools_dir / "pwnenv.mako").exists()
    assert (paths.tools_dir / "tmux.config").exists()
    assert (paths.tools_dir / "tmux-sidebar" / "sidebar.tmux").exists()
    # Legacy removed
    assert not legacy.exists()


def test_main_unknown_options_exit(monkeypatch, capsys, tmp_path):
    mod = load_cli_module()
    # Avoid real setup side effects
    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "load_config", lambda: {"challenges_dir": str(tmp_path / "challs")})

    monkeypatch.setenv("PYTHONPATH", str(tmp_path))

    # Simulate unknown option with a subcommand to trigger the unknown-args branch
    import sys

    old_argv = sys.argv[:]
    sys.argv = ["pwnenv", "init", "--unknown-opt"]
    try:
        try:
            mod.main()
        except SystemExit as exc:  # expected
            assert exc.code == 1
    finally:
        sys.argv = old_argv
    out = capsys.readouterr().out
    assert "Options inconnues" in out


def test_handle_go_success_and_missing(monkeypatch, tmp_path):
    mod = load_cli_module()
    # Prepare paths and a fake project
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    project = paths.challenges_dir / "Proj"
    project.mkdir(parents=True)

    # Success path: exec_shell should be called
    called = {"ok": False}
    def fake_exec(target_dir, p, name):
        assert target_dir == project
        assert name == "Proj"
        called["ok"] = True
    monkeypatch.setattr(mod, "exec_shell", fake_exec)
    ns = types.SimpleNamespace(project_name="Proj")
    mod.handle_go(ns, paths)
    assert called["ok"]

    # Missing project should exit with error
    ns2 = types.SimpleNamespace(project_name="NotExists")
    try:
        mod.handle_go(ns2, paths)
        assert False, "Expected SystemExit"
    except SystemExit:
        pass


def test_handle_init_local_with_libc_and_template(monkeypatch, tmp_path):
    mod = load_cli_module()

    # Prepare a fake local binary and libc
    local_bin = tmp_path / "chall"
    local_bin.write_bytes(b"#!/bin/sh\n")
    libc_file = tmp_path / "libc-2.35.so"
    libc_file.write_text("libc")

    # Prepare template
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "pwnenv.mako").write_text("#!/usr/bin/env python3\nprint('tpl')\n")

    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    # Override script_dir/tools discovery to point to our temp tools
    paths.script_dir = tmp_path
    (paths.script_dir / "tools").mkdir(exist_ok=True)
    (paths.script_dir / "tools" / "pwnenv.mako").write_text((tools / "pwnenv.mako").read_text())

    # Stub out external effects
    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    called = {"exec": False}
    monkeypatch.setattr(mod, "exec_shell", lambda *a, **k: called.__setitem__("exec", True))
    # Avoid running 'pwn template'; force fallback by making subprocess.run raise
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(Exception("no pwn")))

    # Build args namespace similar to argparse
    ns = types.SimpleNamespace(
        project_name="ProjLocal",
        source_path=None,
        local=str(local_bin),
        ssh=None,
        ssh_host=None,
        ssh_user=None,
        ssh_port=None,
        ssh_pass=None,
        ssh_bin=None,
        ssh_src=None,
        libc=str(libc_file),
        source_path_option=None,
    )

    mod.handle_init(ns, paths)

    proj = paths.challenges_dir / "ProjLocal"
    assert (proj / "bin" / local_bin.name).exists()
    assert (proj / "lib").exists()
    assert (proj / "exploit.py").exists()
    # Config should include binary_path_local and libc.local
    conf = json.loads((proj / "pwnenv.conf.json").read_text())
    assert conf["binary_path_local"] == f"./bin/{local_bin.name}"
    assert conf.get("libc", {}).get("local", "").startswith("./lib/")
    assert called["exec"] is True


def test_handle_init_ssh_and_libc_version_with_fallback(monkeypatch, tmp_path):
    mod = load_cli_module()

    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    paths.script_dir = tmp_path
    (paths.script_dir / "tools").mkdir(exist_ok=True)
    # No template provided so command defaults and we still force fallback

    # Stub external effects
    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    called = {"exec": False}
    monkeypatch.setattr(mod, "exec_shell", lambda *a, **k: called.__setitem__("exec", True))
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(Exception("no pwn")))

    ns = types.SimpleNamespace(
        project_name="ProjSSH",
        source_path=None,
        local=None,
        ssh="user@host:/opt/bin/chall",
        ssh_host=None,
        ssh_user=None,
        ssh_port=2222,
        ssh_pass="pwd",
        ssh_bin=None,
        ssh_src="/opt/src",
        libc="2.35",
        source_path_option=None,
    )

    mod.handle_init(ns, paths)
    proj = paths.challenges_dir / "ProjSSH"
    conf = json.loads((proj / "pwnenv.conf.json").read_text())
    assert conf["binary_path_local"] is None
    assert conf["ssh"]["host"] == "host"
    assert conf["ssh"]["user"] == "user"
    assert conf["ssh"]["bin"] == "/opt/bin/chall"
    assert conf["ssh"]["port"] == 2222
    assert conf["ssh"]["pass"] == "pwd"
    assert conf["ssh"]["src"] == "/opt/src"
    assert conf.get("libc", {}).get("version") == "2.35"
    assert (proj / "exploit.py").exists()
    assert called["exec"] is True


def test_handle_init_errors(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)

    # Missing project name
    ns = types.SimpleNamespace(
        project_name=None,
        source_path=None,
        local=None,
        ssh=None,
        ssh_host=None,
        ssh_user=None,
        ssh_port=None,
        ssh_pass=None,
        ssh_bin=None,
        ssh_src=None,
        libc=None,
        source_path_option=None,
    )
    try:
        mod.handle_init(ns, paths)
        assert False, "Expected SystemExit for missing project name"
    except SystemExit:
        pass

    # Project already exists should exit with error
    existing = types.SimpleNamespace(**{**ns.__dict__, "project_name": "Exists"})
    existing_path = paths.challenges_dir / "Exists"
    existing_path.mkdir(parents=True)
    try:
        mod.handle_init(existing, paths)
        assert False, "Expected SystemExit for existing project"
    except SystemExit:
        pass

    # Invalid local path
    ns2 = types.SimpleNamespace(**{**ns.__dict__, "project_name": "PBad", "local": str(tmp_path / "nope.bin")})
    try:
        mod.handle_init(ns2, paths)
        assert False, "Expected SystemExit for invalid local path"
    except SystemExit:
        pass


def test_ensure_password_prompts(monkeypatch):
    mod = load_cli_module()
    # Patch getpass to simulate user input
    monkeypatch.setattr(mod, "getpass", lambda prompt: "secret")
    data = {"host": "h", "user": "u"}
    mod.ensure_password(data)
    assert data["pass"] == "secret"
