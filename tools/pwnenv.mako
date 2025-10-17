<%page args="binary=None, host=None, port=None, user=None, password=None, libc=None, remote_path=None, quiet=False"/>
<%
import json
import os
import sys

from pwnlib.context import context as ctx
from pwnlib.elf.elf import ELF
from pwnlib.util.sh_string import sh_string
from elftools.common.exceptions import ELFError

argv = list(sys.argv)
argv[0] = os.path.basename(argv[0])

conf = {}
try:
    with open("pwnenv.conf.json", "r", encoding="utf-8") as fp:
        conf = json.load(fp)
except Exception:
    conf = {}

libc_section = conf.get("libc") if isinstance(conf.get("libc"), dict) else {}
binary_default = binary or conf.get("binary_path_local") or "./bin/challenge"
libc_default = libc or libc_section.get("local") or libc_section.get("version")

try:
    if binary_default:
        ctx.binary = ELF(binary_default, checksec=False)
except ELFError:
    pass

binary_repr = repr(binary_default)
libc_repr = repr(libc_default)
%>
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
% if not quiet:
# This exploit template was generated via:
# $ ${' '.join(map(sh_string, argv))}
% endif
import os

from pwn import *
from pwnapi import Pipeline

pipeline = Pipeline()
pipeline.print_summary()

LOCAL_BIN = args.EXE or pipeline.binary_path or ${binary_repr}
LOCAL_BIN = str(LOCAL_BIN) if LOCAL_BIN else None
LIBC_PATH = args.LIBC or pipeline.libc_path or ${libc_repr}
LIBC_PATH = str(LIBC_PATH) if LIBC_PATH else None

if LOCAL_BIN and os.path.exists(LOCAL_BIN):
    context.binary = ELF(LOCAL_BIN, checksec=False)
    exe = context.binary
else:
    exe = LOCAL_BIN

if LIBC_PATH and os.path.exists(LIBC_PATH):
    libc = ELF(LIBC_PATH, checksec=False)
else:
    libc = None

gdb_lines = ["continue"]
if context.binary:
    if "main" in context.binary.symbols:
        gdb_lines.insert(0, "tbreak main")
    elif getattr(context.binary, "entry", 0):
        gdb_lines.insert(0, f"tbreak *0x{context.binary.entry:x}")
gdbscript = "\n".join(gdb_lines)

# ---------------------------------------------------------------------------
# Pipeline steps examples
# ---------------------------------------------------------------------------

@pipeline.step
def leaks(self, tube):
    """Collect initial data/leaks."""
    log.info("Reading banner...")
    try:
        banner = tube.recvline(timeout=2)
        log.info("Banner: %r", banner.strip())
    except EOFError:
        log.warning("No banner received")


@pipeline.step
def exploit(self, tube):
    """Exploit logic placeholder."""
    payload = b"A" * 16
    log.info("Sending placeholder payload (%d bytes)", len(payload))
    tube.sendline(payload)


@pipeline.step
def post(self, tube):
    """Post-exploitation stage."""
    log.info("Switching to interactive mode")


if __name__ == "__main__":
    mode = pipeline.choose_mode()
    pipeline.run(mode, gdbscript=gdbscript)
