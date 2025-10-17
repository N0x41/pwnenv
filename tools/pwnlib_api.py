from pwn import *
import json
from pathlib import Path


class Pipeline:
    def __init__(self, os: str = 'linux', arch: str = 'amd64', endian: str = 'little', log_level: str = 'INFO'):
        self.conf = {}
        conf_path = Path('pwnenv.conf.json')
        if conf_path.exists():
            with conf_path.open('r') as f:
                self.conf = json.load(f)

        self.binary_path = self.conf.get('binary_path_local')
        ssh_section = self.conf.get('ssh', {})
        self.ssh_conf = ssh_section if isinstance(ssh_section, dict) else {}
        libc_section = self.conf.get('libc', {})
        self.libc_conf = libc_section if isinstance(libc_section, dict) else {}
        self.libc_path = self.libc_conf.get('local')
        self.libc_version = self.libc_conf.get('version')

        context(os=os, arch=arch, endian=endian)
        context.log_level = log_level
        context.terminal = ['tmux', 'splitw', '-v']

        self.elf = context.binary = ELF(self.binary_path, checksec=False) if self.binary_path else None
        self.p = None
        self.steps = []
        self.state = {}

    def connect(self, mode: str = 'LOCAL', breakpoint=None):
        if mode == 'DEBUG':
            if not self.binary_path:
                log.error("Chemin du binaire requis pour DEBUG.")
                exit(1)
            gdbscript = "source /usr/share/pwndbg/gdbinit.py\n"
            if breakpoint:
                if isinstance(breakpoint, int):
                    gdbscript += f'break *{hex(breakpoint)}\n'
                else:
                    gdbscript += f'break {breakpoint}\n'
            gdbscript += "continue"
            self.p = gdb.debug(self.binary_path, gdbscript=gdbscript)
        elif mode == 'REMOTE':
            required_keys = ['host', 'user', 'bin']
            missing = [k for k in required_keys if not self.ssh_conf.get(k)]
            if missing:
                log.error(f"Infos SSH manquantes dans pwnenv.conf.json: {', '.join(missing)}")
                exit(1)
            ssh_kwargs = {
                'host': self.ssh_conf.get('host'),
                'user': self.ssh_conf.get('user'),
            }
            if self.ssh_conf.get('port'):
                ssh_kwargs['port'] = self.ssh_conf['port']
            if self.ssh_conf.get('pass'):
                ssh_kwargs['password'] = self.ssh_conf['pass']
            ssh_conn = ssh(**ssh_kwargs)
            self.p = ssh_conn.process(self.ssh_conf.get('bin'))
        else:  # LOCAL
            if not self.binary_path:
                log.error("Chemin du binaire requis pour LOCAL.")
                exit(1)
            self.p = process(self.binary_path)
        return self.p

    def step(self, func):
        self.steps.append(func)
        return func

    def run(self, mode: str = 'LOCAL', breakpoint=None):
        p = self.connect(mode, breakpoint)
        if not self.steps:
            log.warning("Aucune étape définie. Passage en mode interactif.")
        try:
            for func in self.steps:
                log.info(f"--- Étape : {func.__name__} ---")
                func(self, p)
            log.success("Toutes les étapes exécutées.")
            if p and p.connected():
                p.interactive()
        except Exception as e:
            log.error(f"Erreur du pipeline : {e}")
        finally:
            if p and p.connected():
                p.close()


