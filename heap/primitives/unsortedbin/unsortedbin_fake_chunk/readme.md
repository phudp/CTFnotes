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

char x[0x600];

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

(update later)

</p>
</details>

<details>
<summary><strong>Ref</strong></summary>
<p>

(update later)

</p>
</details>