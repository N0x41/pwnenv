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


def test_build_parser_parses_init_flags():
    mod = load_cli_module()
    parser = mod.build_parser()
    args, unknown = parser.parse_known_args([
        "init", "Proj", "./src.py",
        "--local", "./bin/chal",
        "--ssh", "user@host:/opt/chal",
        "--ssh-host", "h", "--ssh-user", "u",
        "--ssh-port", "2222",
        "--ssh-pass", "pw",
        "--ssh-bin", "/bin/c",
        "--ssh-src", "/src",
        "--libc", "2.35",
        "--source-path", "./alt.py",
    ])
    assert args.command == "init"
    assert args.project_name == "Proj"
    assert args.source_path == "./src.py"
    assert args.local == "./bin/chal"
    assert args.ssh == "user@host:/opt/chal"
    assert args.ssh_host == "h"
    assert args.ssh_user == "u"
    assert args.ssh_port == 2222
    assert args.ssh_pass == "pw"
    assert args.ssh_bin == "/bin/c"
    assert args.ssh_src == "/src"
    assert args.libc == "2.35"
    assert args.source_path_option == "./alt.py"


def test_handle_init_uses_template_output(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    paths.script_dir = tmp_path
    (paths.script_dir / "tools").mkdir(exist_ok=True)
    (paths.script_dir / "tools" / "pwnenv.mako").write_text("## tpl\n")

    # Prepare args: no local bin, no ssh -> template not given a binary
    ns = types.SimpleNamespace(
        project_name="ProjTpl",
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

    # Mock subprocess.run to emulate pwn template output
    class Dummy:
        def __init__(self, stdout):
            self.stdout = stdout
    tpl_code = "#!/usr/bin/env python3\nprint('hello from template')\n"
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: Dummy(tpl_code))
    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)

    mod.handle_init(ns, paths)
    out = (paths.challenges_dir / "ProjTpl" / "exploit.py").read_text()
    assert "hello from template" in out


def test_handle_init_invalid_ssh_errors(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)

    ns = types.SimpleNamespace(
        project_name="BadSSH",
        source_path=None,
        local=None,
        ssh="user_at_host_without_colon",
        ssh_host=None,
        ssh_user=None,
        ssh_port=None,
        ssh_pass=None,
        ssh_bin=None,
        ssh_src=None,
        libc=None,
        source_path_option=None,
    )

    import sys
    try:
        mod.handle_init(ns, paths)
        assert False, "Expected SystemExit for invalid ssh spec"
    except SystemExit:
        pass


def test_handle_init_template_cmd_includes_template_and_binary(monkeypatch, tmp_path):
    mod = load_cli_module()
    # Prepare local binary
    local_bin = tmp_path / "bin_local"
    local_bin.write_text("x")

    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    paths.script_dir = tmp_path
    (paths.script_dir / "tools").mkdir(exist_ok=True)
    template_file = paths.script_dir / "tools" / "pwnenv.mako"
    template_file.write_text("## tpl\n")

    captured = {}

    class Dummy:
        def __init__(self, stdout):
            self.stdout = stdout

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return Dummy("print('ok')\n")

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)

    ns = types.SimpleNamespace(
        project_name="ProjLocalTpl",
        source_path=None,
        local=str(local_bin),
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

    mod.handle_init(ns, paths)
    cmd = captured.get("cmd")
    assert cmd is not None and cmd[:2] == ["pwn", "template"]
    assert "--template" in cmd and str(template_file) in cmd
    assert f"./bin/{local_bin.name}" in cmd