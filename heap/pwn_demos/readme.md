## Techniques

Leverage heap's bugs/primitives to get code execution.

<details>
<summary><strong>RCE targets</strong></summary>
<p>

- **libc GOT entries**
	- [docs](/heap/pwn_demos/rce_targets/got_libc/readme.md)
	> similar to GOT overwrite...

</p>
</details>

<details>
<summary><strong>Houses</strong></summary>
<p>

- **House of botcake**
	- [docs](/heap/pwn_demos/houses/house_of_botcake/readme.md)
	> **double free primitive**, bypass tcache dbf's key check, making overlapping chunk, return arbitrary allocation...

</p>
</details>

<details>
<summary><strong>Uncategorized (but worth reading)</strong></summary>
<p>

- **Heap seccomp exploitation**
	- [lkmidas's glibc 2.31 heap seccomp exploitation using ROP](/heap/pwn_demos/uncategorized/heap_seccomp/readme.md)
	- [for higer glibc verisons using ROP + ???](/heap/pwn_demos/uncategorized/heap_seccomp/readme01.md)

</p>
</details>