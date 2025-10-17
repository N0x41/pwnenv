<%page args="binary, host=None, port=None, user=None, password=None, libc=None, remote_path=None, quiet=False"/>
<%
import os
import sys
import json

from pwnlib.context import context as ctx
from pwnlib.elf.elf import ELF
from elftools.common.exceptions import ELFError

argv = list(sys.argv)
argv[0] = os.path.basename(argv[0])

# Charger la configuration pwnenv.conf.json si disponible pour définir des valeurs par défaut
conf = {}
try:
    with open('pwnenv.conf.json', 'r') as f:
        conf = json.load(f)
except Exception:
    conf = {}

conf_binary = conf.get('binary_path_local')
conf_host = conf.get('ssh_host')
conf_port = conf.get('ssh_port')
conf_user = conf.get('ssh_user')
conf_password = conf.get('ssh_password')
conf_remote_path = conf.get('binary_path_remote')

binary = binary or conf_binary
host = host or conf_host
port = port or conf_port
user = user or conf_user
password = password or conf_password
remote_path = remote_path or conf_remote_path

try:
    if binary:
       ctx.binary = ELF(binary, checksec=False)
except ELFError:
    pass

if not binary:
    binary = './path/to/binary'

exe = os.path.basename(binary)

ssh = user or password
if ssh and not port:
    port = 22
elif host and not port:
    port = 4141

remote_path = remote_path or exe
password = password or 'secret1234'
binary_repr = repr(binary)
libc_repr = repr(libc)
%>
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
%if not quiet:
# This exploit template was generated via:
# $ ${' '.join(map(sh_string, argv))}
%endif
from pwn import *
from pwnlib_api import Pipeline  # API pwnenv disponible dans le template

%if not quiet:
# Set up pwntools for the correct architecture
%endif
%if ctx.binary or not host:
exe = context.binary = ELF(args.EXE or ${binary_repr})
<% binary_repr = 'exe.path' %>
%else:
context.update(arch='i386')
exe = ${binary_repr}
<% binary_repr = 'exe' %>
%endif

%if not quiet:
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
%if host or port or user:
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
%endif
%endif
%if host:
host = args.HOST or ${repr(host)}
%endif
%if port:
port = int(args.PORT or ${port})
%endif
%if user:
user = args.USER or ${repr(user)}
password = args.PASSWORD or ${repr(password)}
%endif
%if ssh:
remote_path = ${repr(remote_path)}
%endif

%if ssh:
# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)
%endif

%if libc:
%if not quiet:
# Use the specified remote libc version unless explicitly told to use the
# local system version with the `LOCAL_LIBC` argument.
# ./exploit.py LOCAL LOCAL_LIBC
%endif
if args.LOCAL_LIBC:
    libc = exe.libc
%if host:
elif args.LOCAL:
%else:
else:
%endif
    library_path = libcdb.download_libraries(${libc_repr})
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(${binary_repr}, library_path)
        libc = exe.libc
    else:
        libc = ELF(${libc_repr})
%if host:
else:
    libc = ELF(${libc_repr})
%endif
%endif

%if host:
def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([${binary_repr}] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([${binary_repr}] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
  %if ssh:
    '''Execute the target binary on the remote host'''
    if args.GDB:
        return gdb.debug([remote_path] + argv, gdbscript=gdbscript, ssh=shell, *a, **kw)
    else:
        return shell.process([remote_path] + argv, *a, **kw)
  %else:
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io
  %endif
%endif

%if host:
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)
%else:
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([${binary_repr}] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([${binary_repr}] + argv, *a, **kw)
%endif

%if exe or remote_path:
%if not quiet:
# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
%endif
gdbscript = '''
%if ctx.binary:
  %if 'main' in ctx.binary.symbols:
tbreak main
  %elif 'DYN' != ctx.binary.elftype:
tbreak *0x{exe.entry:x}
  %endif
%endif
continue
'''.format(**locals())
%endif


%if not quiet:
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
%else:
# -- Exploit goes here --
%endif
%if ctx.binary and not quiet:
# ${'%-10s%s-%s-%s' % ('Arch:',
                       ctx.binary.arch,
                       ctx.binary.bits,
                       ctx.binary.endian)}
%for line in ctx.binary.checksec(color=False).splitlines():
# ${line}
%endfor
%endif

io = start()

%if not quiet:
# Exemple d'utilisation de l'API pwnenv si souhaité:
# from pwnlib_api import Pipeline
# pipeline = Pipeline()
# @pipeline.step
# def example_step(self, p):
#     log.info("Hello from pwnenv Pipeline")
# pipeline.run('LOCAL')
%endif

io.interactive()
