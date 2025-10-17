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
            ssh_conf = {k: self.conf.get(f"ssh_{k}") for k in ['host', 'port', 'user', 'password']}
            if not all(ssh_conf.values()):
                log.error("Infos SSH manquantes dans pwnenv.conf.json")
                exit(1)
            ssh_conn = ssh(**ssh_conf)
            self.p = ssh_conn.process(self.conf.get('binary_path_remote'))
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


