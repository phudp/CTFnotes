## Techniques

Leverage heap's bugs/primitives to get code execution.

### Remote code execution

<details>
<summary><strong>Targetting</strong></summary>
<p>

- **libc GOT entries**
	- [docs](../pwn_demos/targetting/got_libc/readme.md)
	> similar to GOT overwrite...

</p>
</details>

<details>
<summary><strong>Houses</strong></summary>
<p>

- **House of botcake**
	- [docs](../pwn_demos/houses/house_of_botcake/readme.md)
	> **double free primitive**, bypass tcache dbf's key check, making overlapping chunk, return arbitrary allocation...

</p>
</details>

