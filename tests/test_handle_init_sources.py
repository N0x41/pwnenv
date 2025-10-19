from __future__ import annotations

from pathlib import Path
import types
import json


def load_cli_module():
    cli_path = Path(__file__).resolve().parents[1] / "pwnenv"
    code = cli_path.read_text()
    module = types.ModuleType("pwnenv_cli")
    module.__file__ = str(cli_path)
    compiled = compile(code, str(cli_path), "exec")
    exec(compiled, module.__dict__)
    return module


def test_handle_init_copies_source_file(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    # Prepare source file
    source_file = tmp_path / "seed.py"
    source_file.write_text("print('x')\n")

    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(Exception("no pwn")))

    ns = types.SimpleNamespace(
        project_name="WithFile",
        source_path=str(source_file),
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
    mod.handle_init(ns, paths)
    proj = paths.challenges_dir / "WithFile"
    assert (proj / "src" / source_file.name).exists()


def test_handle_init_copies_source_dir(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)
    # Prepare source directory with a file
    source_dir = tmp_path / "seed_dir"
    (source_dir).mkdir()
    (source_dir / "a.txt").write_text("a\n")

    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(Exception("no pwn")))

    ns = types.SimpleNamespace(
        project_name="WithDir",
        source_path=str(source_dir),
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
    mod.handle_init(ns, paths)
    proj = paths.challenges_dir / "WithDir"
    assert (proj / "src" / source_dir.name / "a.txt").exists()


def test_handle_init_ssh_flags_without_spec(monkeypatch, tmp_path):
    mod = load_cli_module()
    cfg = {"challenges_dir": str(tmp_path / "challs")}
    paths = mod.Paths(cfg)

    monkeypatch.setattr(mod, "self_setup", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *_a, **_k: None)
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(Exception("no pwn")))

    ns = types.SimpleNamespace(
        project_name="SSHOnlyFlags",
        source_path=None,
        local=None,
        ssh=None,
        ssh_host="h",
        ssh_user="u",
        ssh_port=2022,
        ssh_pass="p",
        ssh_bin="/bin/chall",
        ssh_src="/src",
        libc=None,
        source_path_option=None,
    )
    mod.handle_init(ns, paths)
    conf = json.loads((paths.challenges_dir / "SSHOnlyFlags" / "pwnenv.conf.json").read_text())
    assert conf["ssh"]["host"] == "h"
    assert conf["ssh"]["user"] == "u"
    assert conf["ssh"]["port"] == 2022
    assert conf["ssh"]["pass"] == "p"
    assert conf["ssh"]["bin"] == "/bin/chall"
    assert conf["ssh"]["src"] == "/src"
