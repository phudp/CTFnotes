some pwn processes related to FSOP

- [stdout 0.5](/fsop/pwn_demos/stdout05/readme.md)
> using `stdout` as read primitive and `stdout 0.5` trick...

- [stdin's buffer expansion](/fsop/pwn_demos/stdin_buffer_expansion/readme.md)
> using one byte (or more) overwrite to expand `stdin`'s buffer then write over `stdout` for fsop...

- [overwrite `_IO_list_all`](/fsop/pwn_demos/io_list_all/readme.md)
> abusing `_IO_list_all` - a good target in high glibc versions...
