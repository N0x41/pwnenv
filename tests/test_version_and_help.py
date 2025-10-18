from pathlib import Path
import types


def load_cli_module() -> types.ModuleType:
    cli_path = Path(__file__).resolve().parents[1] / "pwnenv"
    code = cli_path.read_text()
    module = types.ModuleType("pwnenv_cli")
    compiled = compile(code, str(cli_path), "exec")
    exec(compiled, module.__dict__)
    return module


def test_version_constant_present():
    mod = load_cli_module()
    assert hasattr(mod, "PWNENV_VERSION")
    assert isinstance(mod.PWNENV_VERSION, str)
    assert mod.PWNENV_VERSION.count(".") >= 1


def test_show_help_prints_usage(monkeypatch, capsys, tmp_path):
    mod = load_cli_module()

    # Monkeypatch heavy operations to avoid side effects during tests
    monkeypatch.setattr(mod, "self_setup", lambda *_args, **_kw: None)
    monkeypatch.setattr(mod, "exec_shell", lambda *a, **k: None)
    monkeypatch.setattr(mod, "load_config", lambda: {"challenges_dir": str(tmp_path / "challs")})

    # Call show_help directly to exercise help path
    mod.show_help()
    out = capsys.readouterr().out
    assert "Usage:" in out or "usage:" in out

    # Also ensure parser has expected subcommands
    parser = mod.build_parser()
    # The subparsers store choices in ._subparsers actions
    # Check presence of our commands via help text
    text = parser.format_help()
    assert "init" in text and "go" in text
