# giftshop

ROP && SROP

1. bof -> fgets
2. sys read (0)
3. sys sig_return (15)
4. sys execveat (322)

The server block some syscall.
