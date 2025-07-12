## Primitives

Various "pure (heap's) primitives" we can (ab)use for futher exploitation.

### Malloc

<details>
<summary><strong>Overlapping chunk via consolidation</strong></summary>
<p>

- **Foward consolidation**
	- [docs](/heap/primitives/malloc/foward_consolidation/readme.md)
	> using forward consolidation to get overlapping memory...

- **Backward consolidation**
	- [docs](/heap/primitives/malloc/backward_consolidation/readme.md)
	> using back consolidation to reallocate a chunk that wasn't freed...

- **Overlapping consolidation**
	- [docs](/heap/primitives/malloc/overlapping_consolidation/readme.md)
	> using consolidation to reallocate a chunk that wasn't freed...

- **Top consolidation**
	- [docs](/heap/primitives/malloc/top_consolidation/readme.md)
	> using top chunk consolidation to reallocate a chunk that wasn't freed...

- **Overlapping mmap**
	- link
	> abc

</p>
</details>

<details>
<summary><strong>Unlinking</strong></summary>
<p>

- **Unsafe unlink**
	- link
	> abc

</p>
</details>

### Tcache

<details>
<summary><strong>Tcache linked list attack</strong></summary>
<p>

- **Tcache poisoning**
	- [docs](/heap/primitives/tcache/tcache_poisoning/readme.md)
	> poisoning next ptr of tcache bin to get arbitrary allocate...

</p>
</details>

<details>
<summary><strong>Tcache double free</strong></summary>
<p>

- **Tcache key double**
	- [docs](/heap/primitives/tcache/tcache_key_double/readme.md)
	> successful tcache double free via modify tcache chunk's key...

- **Tcache fastbin double**
	- [docs](/heap/primitives/tcache/tcache_fastbin_double/readme.md)
	> successful tcache double free between tcache/fastbin...

- **Tcache size double**
	- [docs](/heap/primitives/tcache/tcache_size_double/readme.md)
	> successful tcache double free between different size...

</p>
</details>

<details>
<summary><strong>Free custom tcache chunk</strong></summary>
<p>

- **Tcache fake chunk**
	- [docs](/heap/primitives/tcache/tcache_fake_chunk/readme.md)
	> inserting a fake chunk with free into the tcache...

</p>
</details>

### Fastbin

<details>
<summary><strong>Fastbin linked list attack</strong></summary>
<p>

- **Fastbin poisoning**
	- [docs](/heap/primitives/fastbin/fastbin_poisoning/readme.md)
	> poisoning next ptr of fastbin to get arbitrary allocate...

</p>
</details>

<details>
<summary><strong>Fastbin double free</strong></summary>
<p>

- **Fastbin double**
	- [docs](/heap/primitives/fastbin/fastbin_double/readme.md)
	> successful fastbin double free...

</p>
</details>

<details>
<summary><strong>Free custom fastbin chunk</strong></summary>
<p>

- **Fastbin fake chunk**
	- link
	> abc

</p>
</details>

### Unsortedbin

<details>
<summary><strong>Overlapping chunk via unsortedbin</strong></summary>
<p>

- **Unsortedbin exact fit**
	- [docs](/heap/primitives/unsortedbin/unsortedbin_exact_fit/readme.md)
	> allocate overlapping chunks via exact fit mechanism...

- **Unsortedbin last remainder**
	- [docs](/heap/primitives/unsortedbin/unsortedbin_last_remainder/readme.md)
	> reallocate allocated chunks without freeing, via leveraging the last_remainder...

</p>
</details>

<details>
<summary><strong>Unsortedbin linked list attack</strong></summary>
<p>

- **Unsortedbin poisoning**
	- [docs](/heap/primitives/unsortedbin/unsortedbin_poisoning/readme.md)
	> allocate chunk into stack leveraging unsortedbin linked list...

- **Unsortedbin attack (?)**
	- link
	> abc

</p>
</details>

<details>
<summary><strong>Free custom unsortedbin chunk</strong></summary>
<p>

- **Unsortedbin fake chunk**
	- link
	> abc

</p>
</details>

### Largebin

<details>
<summary><strong>Largebin linked/skip list attack</strong></summary>
<p>

- **Largebin linked poisoning**
	- [docs](/heap/primitives/largebin/largebin_linked_poisoning/readme.md)
	> allocate chunk into stack leveraging large bin linked list...

- **Largebin skip poisoning**
	- [docs](/heap/primitives/largebin/largebin_skip_poisoning/readme.md)
	> allocate chunk into stack leveraging large bin skip list...

- **Largebin attack**
	- [docs](/heap/primitives/largebin/largebin_attack/readme.md)
	> write a heap address to arbitrary memory location...

</p>
</details>

### Smallbin

<details>
<summary><strong>Smallbin linked list attack</strong></summary>
<p>

- **Smallbin poisoning**
	- [docs](/heap/primitives/smallbin/smallbin_poisoning/readme.md)
	> allocate chunk into the stack leveraging small bin linked list...

</p>
</details>
