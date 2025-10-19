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
