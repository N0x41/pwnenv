#!/usr/bin/env python3
import argparse
import shutil
import stat
import json
import subprocess
from pathlib import Path


EXPLOIT_PY_FALLBACK = """#!/usr/bin/env python3
from pwn import *


def main():
    print("Template généré par pwnenv (fallback). Lancez 'pwn template' pour un squelette pwntools complet.")


if __name__ == '__main__':
    main()
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("project_path", type=Path)
    parser.add_argument("--binary-path", type=Path, default=None)
    parser.add_argument("--ssh-host", type=str)
    parser.add_argument("--ssh-port", type=int)
    parser.add_argument("--ssh-user", type=str)
    parser.add_argument("--ssh-password", type=str)
    parser.add_argument("--ssh-remote-path", type=str)
    parser.add_argument("--source-path", type=Path, default=None)
    args = parser.parse_args()

    project_dir, binary_path = args.project_path, args.binary_path
    if project_dir.exists():
        print(f"❌ Erreur : '{project_dir}' existe déjà.")
        exit(1)

    bin_dir = project_dir / 'bin'
    src_dir = project_dir / 'src'
    src_dir.mkdir(parents=True)

    binary_name = None
    if binary_path:
        bin_dir.mkdir()
        binary_name = binary_path.name
        dest_binary = bin_dir / binary_name
        shutil.copy(binary_path, dest_binary)
        dest_binary.chmod(dest_binary.stat().st_mode | stat.S_IEXEC)

    config = {
        'binary_path_local': f"./bin/{binary_name}" if binary_name else None,
        'binary_path_remote': args.ssh_remote_path,
        'ssh_host': args.ssh_host,
        'ssh_port': args.ssh_port,
        'ssh_user': args.ssh_user,
        'ssh_password': args.ssh_password,
    }

    with (project_dir / 'pwnenv.conf.json').open('w') as f:
        json.dump(config, f, indent=4)

    # Si une source est fournie, la copier dans src/
    if args.source_path:
        src_dir.mkdir(exist_ok=True)
        if args.source_path.is_dir():
            dest_folder = src_dir / args.source_path.name
            shutil.copytree(args.source_path, dest_folder, dirs_exist_ok=True)
        else:
            dest_source = src_dir / args.source_path.name
            shutil.copy2(args.source_path, dest_source)

    # Génération du template via 'pwn template'
    exploit_script_path = project_dir / 'exploit.py'
    template_cmd = ["pwn", "template", "--template", str(Path(__file__).with_name("pwnenv.mako"))]
    # Préférer le binaire local si disponible, sinon utiliser host/port si fournis
    local_bin_path = None
    if binary_name:
        local_bin_path = f"./bin/{binary_name}"
        template_cmd.append(local_bin_path)
    else:
        # Passer toutes les options pertinentes supportées par pwn template
        if args.ssh_host:
            template_cmd += ["--host", str(args.ssh_host)]
        if args.ssh_port:
            template_cmd += ["--port", str(args.ssh_port)]
        if args.ssh_user:
            template_cmd += ["--user", str(args.ssh_user)]
        if args.ssh_password:
            template_cmd += ["--pass", str(args.ssh_password)]
        if args.ssh_remote_path:
            template_cmd += ["--path", str(args.ssh_remote_path)]

    try:
        tpl = subprocess.run(template_cmd, check=True, capture_output=True, text=True)
        exploit_script_path.write_text(tpl.stdout)
    except Exception:
        # Fallback minimal si 'pwn template' n'est pas disponible
        exploit_script_path.write_text(EXPLOIT_PY_FALLBACK)
    exploit_script_path.chmod(0o755)
    print(f"✅ Structure du projet '{project_dir.name}' créée.")


if __name__ == "__main__":
    main()


