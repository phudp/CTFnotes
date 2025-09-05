purely heap fengshui, my solution is unintended, fck it

update:

i dont remember exactly the details so i will write shortly...

the chall have the bof via `cin` function, make a heap overflow primitive

we have a free heap leak, so we can tcache poisoning to anywhere of the stack. But since the program keep memset everytime allocate chunks, and the terminate null byte from `cin`, we cant perform normaly, or else it will crash the heap chunks metadata, also leaking is harder too.

So first i tcache poisoning to leak PIE

Then tcache poisoning again to create fake unsortebin chunk, abuse the remainder process to drop libc pointer to inuse chunks to get a leak.

> but becareful when the libc pointer will overwrite the struct's vtable pointer

This is how my unintended look like, official solution abuse the fact that some function wont be inherrit so the program call it directly, NOT via indexing vtable. So when the vtable pointer is corrupted, the program wont met any errors. 

But since i have PIE leak, i just simply overwrite it, restore the vtable pointer (Official solution doesnt have leak PIE part)

Then tcache poisoning again to stdout, perform fsop.

There is another way to leak environ and rop to stack which abuse the tcache per thread chunk (at beginning of heap). You can found [here](https://github.com/Nvkiero/CTF_2025/blob/main/SekaiCTF/Learning%20OOP/solve.py)

my full solution can be found in the same folder...

