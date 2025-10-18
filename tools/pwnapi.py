#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Optional

from pwn import ELF, context, gdb, log, process, ssh
from pwnlib.args import args
from pwnlib.tubes.tube import tube


StepFn = Callable[["Pipeline", tube], None]


class Pipeline:
    """Pipeline utilitaire pour orchestrer des étapes d'exploitation.

    Il charge automatiquement la configuration générée par ``pwnenv``
    (``pwnenv.conf.json``) afin de préparer le binaire local, les accès
    distants et, si disponible, la libc associée.
    """

    def __init__(
        self,
        os: str = "linux",
        arch: str = "amd64",
        endian: str = "little",
        log_level: str = "INFO",
    ) -> None:
        self.conf_path = Path("pwnenv.conf.json")
        self.conf: dict = {}
        if self.conf_path.exists():
            try:
                self.conf = json.loads(self.conf_path.read_text())
            except Exception as exc:  # pragma: no cover - logging only
                log.warning(f"Impossible de charger {self.conf_path}: {exc}")

        self.binary_path: Optional[str] = self.conf.get("binary_path_local")
        ssh_section = self.conf.get("ssh") if isinstance(self.conf.get("ssh"), dict) else {}
        self.ssh_conf = ssh_section if ssh_section else {}
        libc_section = self.conf.get("libc") if isinstance(self.conf.get("libc"), dict) else {}
        self.libc_conf = libc_section if libc_section else {}

        self.remote_host: Optional[str] = self.ssh_conf.get("host")
        self.remote_port: Optional[int] = self.ssh_conf.get("port")
        self.remote_user: Optional[str] = self.ssh_conf.get("user")
        self.remote_pass: Optional[str] = self.ssh_conf.get("pass")
        self.remote_path: Optional[str] = self.ssh_conf.get("bin")
        if self.remote_host and self.remote_user and self.remote_path and not self.remote_port:
            self.remote_port = 22

        self.has_remote = all([self.remote_host, self.remote_user, self.remote_path])
        self.has_local = bool(self.binary_path)

        context(os=os, arch=arch, endian=endian)
        context.log_level = log_level
        context.terminal = ["tmux", "splitw", "-v"]

        self.elf: Optional[ELF] = None
        if self.binary_path:
            try:
                self.elf = context.binary = ELF(self.binary_path, checksec=False)
            except Exception as exc:  # pragma: no cover - logging only
                log.warning(f"Impossible de charger le binaire local '{self.binary_path}': {exc}")

        self.libc_path: Optional[str] = self.libc_conf.get("local")
        self.libc_version: Optional[str] = self.libc_conf.get("version")
        self.libc: Optional[ELF] = None
        if self.libc_path:
            try:
                self.libc = ELF(self.libc_path, checksec=False)
            except Exception as exc:  # pragma: no cover - logging only
                log.warning(f"Impossible de charger la libc '{self.libc_path}': {exc}")

        # Steps/pipeline state
        self.steps: list[StepFn] = []
        self._process: Optional[tube] = None
        self._ssh_session = None

    @property
    def default_mode(self) -> str:
        if self.has_remote:
            return "REMOTE"
        if self.has_local:
            return "LOCAL"
        return "REMOTE" if self.remote_host else "LOCAL"

    def choose_mode(self) -> str:
        if getattr(args, "GDB", False):
            if self.has_remote and not self.has_local:
                return "REMOTE"
            return "DEBUG"
        if args.DEBUG:
            return "DEBUG"
        if args.REMOTE:
            return "REMOTE"
        if args.LOCAL:
            return "LOCAL"
        return self.default_mode

    def step(self, func: StepFn) -> StepFn:
        """Décorateur pour enregistrer une étape dans le pipeline."""

        self.steps.append(func)
        return func

    def connect(self, mode: str = "LOCAL", breakpoint=None, gdbscript: Optional[str] = None) -> tube:
        selected = (mode or self.default_mode).upper()
        if getattr(args, "GDB", False) and selected != "DEBUG":
            selected = "DEBUG"
        if selected == "DEBUG":
            if not self.binary_path:
                log.error("Chemin du binaire requis pour le mode DEBUG.")
                raise SystemExit(1)
            script = gdbscript or "source /usr/share/pwndbg/gdbinit.py\n"
            if breakpoint is not None:
                if isinstance(breakpoint, int):
                    script += f"break *{hex(breakpoint)}\n"
                else:
                    script += f"break {breakpoint}\n"
            script += "continue"
            self._process = gdb.debug(self.binary_path, gdbscript=script)
            return self._process

        if selected == "REMOTE":
            if not self.has_remote:
                log.error("Configuration SSH incomplète pour le mode REMOTE.")
                raise SystemExit(1)
            ssh_kwargs = {"host": self.remote_host, "user": self.remote_user}
            if self.remote_port:
                ssh_kwargs["port"] = int(self.remote_port)
            if self.remote_pass:
                ssh_kwargs["password"] = self.remote_pass
            self._ssh_session = ssh(**ssh_kwargs)
            target_path = self.remote_path or self.binary_path
            if not target_path:
                log.error("Aucun chemin de binaire distant défini.")
                raise SystemExit(1)
            command = [target_path] if isinstance(target_path, str) else target_path
            if selected == "REMOTE" and getattr(args, "GDB", False):
                script = gdbscript or "continue"
                self._process = gdb.debug(command, gdbscript=script, ssh=self._ssh_session)
            else:
                self._process = self._ssh_session.process(command)
            return self._process

        if not self.binary_path:
            log.error("Chemin du binaire requis pour le mode LOCAL.")
            raise SystemExit(1)
        self._process = process(self.binary_path)
        return self._process

    def print_summary(self) -> None:
        """Affiche un résumé de la configuration chargée."""

        summary = [
            ("LOCAL", self.binary_path or "-"),
            ("REMOTE", f"{self.remote_user}@{self.remote_host}:{self.remote_path}" if self.has_remote else "-"),
            ("PORT", self.remote_port or "-"),
            ("LIBC", self.libc_path or self.libc_version or "-"),
            ("MODE", self.default_mode),
        ]
        for label, value in summary:
            log.info(f"{label:<6}: {value}")

    def run(self, mode: Optional[str] = None, breakpoint=None, gdbscript: Optional[str] = None) -> None:
        """Exécute les étapes enregistrées puis passe en interaction."""

        selected = (mode or self.default_mode).upper()
        tube_instance = self.connect(selected, breakpoint=breakpoint, gdbscript=gdbscript)
        if not self.steps:
            log.warning("Aucune étape définie. Passage direct en interaction.")
        try:
            for func in self.steps:
                log.info(f"--- Étape : {func.__name__} ---")
                func(self, tube_instance)
            log.success("Toutes les étapes exécutées.")
        except Exception as exc:  # pragma: no cover - logging only
            log.error(f"Erreur du pipeline : {exc}")
        finally:
            try:
                if tube_instance and tube_instance.connected():
                    tube_instance.interactive()
            finally:
                try:
                    if tube_instance and tube_instance.connected():
                        tube_instance.close()
                finally:
                    if self._ssh_session:
                        self._ssh_session.close()