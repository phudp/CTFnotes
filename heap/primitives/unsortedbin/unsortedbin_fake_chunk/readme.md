<details>
<summary><strong>Description</strong></summary>
<p>

this is free a fake unsortedbin's size chunk, different with inserted a fake chunk into unsortedbin (unsortedbin poisoning)...

this is usually exist when we need a libc leak, so we edit some chunk header in heap, prepare some metadata after to bypass check, and free it to make it goes to unsortedbin...

</p>
</details>

<details>
<summary><strong>POC</strong></summary>
<p>

> compiled with glibc `2.31`, `2.35`, `2.38` and `2.39`

```C
#include <stdio.h>
#include <stdlib.h>

char x[0x600]; // fake unsortedbin must below the heap bound

int main()
{
    setbuf(stdin, NULL); // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdout, NULL);

    long *ptr, *chunk;

    malloc(0); // init heap

    // just to make sure ptr is aligned 0x10
    for(int i = 0; i < 0x10; i++) {
        if((((long)&x[i]) & 0xF) == 0) {
            ptr = &x[i];
            break;
        }
    }

    printf("target ptr: %p\n", ptr);

    // prepare few things
    ptr[-1] = 0x511; // fake chunk size (unsortedbin range) (or bigger than fastbin when tcache is fill) (prev_inuse on to prevent backward consolidation)

    ptr[0x500/8 + 1] = 0x21; // fake next adjacent chunk's size (bypass the prev_inuse check)

    ptr[0x500/8 + 0x20/8 + 1] = 0x1; // fake (next adjacent chunk of (next adjacent chunk))'s size (bypass the the prev_inuse, prevent the forward consolidation) (size doesnt matter i guess)

    // VULNERABILITY
    free(ptr);
    // VULNERABILITY

    chunk = malloc(0x508);
    printf("chunk: %p\n", chunk);
}
```

</p>
</details>

<details>
<summary><strong>Explain</strong></summary>
<p>

> the original epxlain was from `heap_lab -> part_2 -> house_of_spirit`, too lazy to rewrite it so i just copy it into here, the glibc version and example might be different but the explain is maybe still helpful (maybe)...

### Unsortedbin

Let's try the House of Spirit with a small chunk.

> Turn on `prev_inuse` bit.

Change the size of our fake chunk from `0x81` to `0x91` by modifying the "age" variable. This puts it in the "normal" chunk size range, making it eligible for unsortedbin insertion on free. If you didn't have the `prev_inuse` bit set before, set it now. You probably remember from the Unsafe Unlink technique that a clear `prev_inuse` flag on a non-fast chunk will cause malloc to consolidate it with the previous chunk.

Not only are we unable to provide a `prev_size` field in this case, even if we could we'd have to satisfy the safe unlinking checks and both size vs prev_size checks, introducing a prohibitive amount of complexity to our exploit. So keep that in `prev_inuse` bit set. 

> Adjacent chunk size and `prev_insue` bit.

Remember to padding more so we can bypass the next chunk size check. Also set the `prev_inuse` bit of next chunk size, or else we will trigger a double-free mitigation.

![](attachments/image03.png)

All it's doing is checking the `prev_inuse` flag of the adjacent chunk. If that flag is clear, that chunk we're trying to free must already be free.

> Adjacent chunk of adjacent chunk.

We're nearly there, but before we change that second size field, consider the following; we've set our fake chunk's `prev_inuse` flag to avoid backward consolidation. But what about forward consolidation? The Unsafe Unlink technique taught us that malloc will also check the `prev_inuse` flag of the chunk after the adjacent chunk. If that's clear, then it will attempt forward consolidation. The easiest way to avoid this is to provide a third fake size field using fencepost chunks. So let's replace the second size field with a fencepost chunk, not forgetting to set its `prev_inuse` flag to avoid triggering the double-free mitigation, then add a padding quadword followed by another fencepost chunk, again with a set `prev_inuse` flag, this time to avoid forward consolidation. This third size field doesn't actually have to be sane so long as it has a set `prev_inuse` flag, making it more likely that we could just find one in memory rather than crafting it ourselves.

Done, after prepare, our fake chunk will look like this:

![](attachments/image04.png)

Its able to free then will go to unsortedbin and ready to re-allocate:

![](attachments/image05.png)

### Attention

> `ptr` is aligned `0x10`.

When we `free` our fake chunk, let make sure that it's address is aligned `0x10`, or else we will trigger mitigation:

![](attachments/image06.png)

> Heap address.

With fake unsortedbin chunk, we also have to make sure our fake chunk is not above heap bound

![](attachments/image07.png)

Remember this doesn't affect to fake fastbin chunk.

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

(update later)

</p>
</details>