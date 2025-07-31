write-up description (updated later)

## non-heap related

<details>
<summary><strong>ROP (or buffer overflow style)</strong></summary>
<p>

- **Dreamhack wargame** --> pop rdi
	- [write-up](/challs/dreamhack/pop_rdi/readme.md)
	> no leak functions, restricted gadget, use stack pivot + add_gadget to modify saved registers values during functions internal...

- **UMDCTF 2025** --> prison realm
	- [write-up](/challs/umdctf/prison_realm/readme.md)
	> no leak functions, use stack pivot + add_gadget -> attack GOT to create custom rop gadget...

- **PWNABLE.TW** --> de aslr
	- [write-up](/challs/pwnabletw/deaslr/readme.md)
	> no leak functions, no add_gadget, use stack pivot + csu gadgets to re(ab)use the left over libc pointer...

- **MetaCTF 2021** --> an attemp was made
	- [write-up](/challs/metactf/an_attempt_was_made/readme.md)
	> seccomp and few gadgets, use add_gadget -> attack GOT to create some custom gadget then calling mprotect to make bss executable...

</p>
</details>

<details>
<summary><strong>Shellcode collection (that's outclassed me)</strong></summary>
<p>

- **angstromCTF 2022** --> parity
	- [write-up](/challs/angstromctf/parity/readme.md)
	> odd/even byte shellcode depend on current position... (bonus tips)

- **UIUCTF 2024** --> syscalls
	- [write-up](/challs/uiuctf/syscalls/readme.md)
	> seccomp restricted some common syscalls... (bonus tips)

- **NahamCon CTF 2022** --> stackless
	- [write-up](/challs/nahamconctf/stackless/readme.md)
	> clear all registers before execute shellcode... (bonus tips)

</p>
</details>

## Heap / FSOP related

<details>
<summary><strong>libc 2.39</strong></summary>
<p>

- **PwnMe CTF Quals 2025** --> compress
	- [write-up](/challs/pwnmectf/compress/readme.md)
	> off by one leads to mismatch pointer, control chunks's metadata, perform unsortedbin poisoning to allocate into stack...

</p>
</details>

<details>
<summary><strong>libc 2.38</strong></summary>
<p>

- **GlacierCTF 2023** -> write byte where
	- [write-up](/challs/glacierctf/write_byte_where/readme.md)
	> one byte arbitrary write, expand stdin buffer, then perform fsop... 

</p>
</details>

<details>
<summary><strong>libc 2.35</strong></summary>
<p>

- **picoCTF 2024** --> high frequency troubles
	- [write-up](/challs/picoctf/high_frequency_troubles/readme.md)
	> obiviously heap overflow but no `free` function, do a trick to free `top_chunk`, abusing overflow primitives to control `tcache_per_thread` in TLS...

</p>
</details>

<details>
<summary><strong>libc 2.34</strong></summary>
<p>

- **MetaCTF 2021** --> hookless
	- [write-up](/challs/metactf/hookless/readme.md)
	> dbf in `delete` function, uaf in `display` function, uaf in `edit` function (usable once) -> custom `house of botcake`, then overwrite libc strlen got entry with one_gadget...

</p>
</details>

<details>
<summary><strong>libc 2.31</strong></summary>
<p>

- **CyberSpace CTF 2024** --> shop
	- [write-up](/challs/cyberspacectf/shop/readme.md)
	> obiviously double free but no leak function, use `stdout 0.5` trick to have a leak then perform fsop...

- **Dreamhack wargame** --> heap chall 1
	- [write-up](/challs/dreamhack/heap_chall_1/readme.md)
	> obviously double free but no leak function, the program auto add a **null byte** after input data, **modify** `stdout 0.5` trick a little to get a leak...

</p>
</details>

## C++ related

<details>
<summary><strong>Uncategorized</strong></summary>
<p>

- **GlacierCTF 2023** --> glacier rating
	- [write-up](/challs/glacierctf/glacier_rating/readme.md)
	> C++ heap style, uninitialized pointer when delete note leads to doube free...

</p>
</details>
