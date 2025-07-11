Folder for binary files and their write-up (updated later)

## Write-ups index

### non-heap related

<details>
<summary><strong>ROP (or buffer overflow style)</strong></summary>
<p>

- **Dreamhack wargame** --> pop rdi
	- [write-up](/challs/dreamhack/pop_rdi/readme.md)
	> no leak functions, restricted gadget, use stack pivot + add_gadget to modify saved registers values during functions internal...

- **UMDCTF 2025** --> prison realm
	- [write-up](/challs/umdctf/prison_realm/readme.md)
	> no leak functions, use stack pivot + add_gadget -> attack GOT to create custom rop gadget...

</p>
</details>

### Heap / FSOP related

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
