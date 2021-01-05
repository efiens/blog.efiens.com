---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "[TetCTF2020] All pwn writeups"
subtitle: ""
summary: "Writeups for TetCTF2020 pwn challenges"
authors: [midas]
tags: []
categories: []
date: 2020-01-08T01:29:07-04:00
lastmod: 2020-01-08T19:46:38-07:00
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

All files can be found [here](https://github.com/lkmidas/Short-CTF-Writeups/tree/master/tetctf2020_all_pwn).

# OANHBOT
- Given files: `oanhbot`, `libc-2.23.so`.
- The binary has: `Partial RELRO`, `Canary found`, `NX enabled` and `No PIE`.
## Functionalities
- In this program, you will name your hero and choose an enemy to fight with and decide who wins.
- Firstly, the program reads 0x10 bytes of input as your hero's name.
- Secondly, you can choose one of the pre-defined name for your enemy, or name it yourself with another 0x10 bytes of input.
- Then, the program will go into a loop that continuously reducing your and your enemy's HP based on your and your enemy's damage. The problem is, all the HPs and damages are hard-coded in a way that you will always lose!
- But if somehow you win, you can say `Y` and then pass in 0x90 bytes of input as a `status`.
## Vulnearabilities
**(1)** In the `read_input()` function, there is a off-by-one null byte overflow if you read in the maximum number of bytes.

**(2)** The characters' `damage` is stored right next to their `name` in the struct, so the null byte overflow will lead to an overflow into the damage.

**(3)** Your `status`, after being read, will be passed directly as a `fmt` parameters for `snprintf`, leads to a format string bug.

## Exploit plan

**Step 1:** Send in any name for your hero, and then a 0x10 byte-long name for the enemy, this will lead to a null byte overflow and set your enemy's damage from `0x1F0` to `0x100`.

**Step 2:** We will win the battle using step 1, choose `Y` to pass in a status, the next step is to exploit the format string bug in the status. Calculate the offset to `main` and `system@plt` to craft the fmt payload.

**Step 3:** Craft the fmt payload in a way that it will overwrite `system@GOT` with `main` and `memset@GOT` with `system@PLT`, then send it.

**Step 4:** `system()` will be called, which is now `main()`, we are now back to main, repeat step 1 to win the battle, and then pass in `Y;sh;` so that we pass the check and get to `memset()`, which is now `system()`, to get the shell.

## Full exploit
See `solve.py`.

# OLDSCHOOL
- Given files: `oldschool`, `libc-2.23.so`.
- The binary has: `Full RELRO`, `Canary found`, `NX enabled` and `PIE enabled`.
- This is an old-school libc 2.23 heap challenge.
## Functionalities
- This program is a simple note that will store data on the heap. It has 4 functionalities: `create` a note, `edit` a note, `show` a note and `delete` a note.
- In `create`, it will first `malloc()` a 0x10 byte chunk, then read in an integer as the size of the note, this small chunk will store the metadata of a note, which is the pointer to the content chunk, the size,  and the note's state (more on this later). Another `malloc()` will be called with the size the user chose to allocate the content chunk. The content itself will be read in afterwards. You can only have at most 10 notes at a time.
- In `edit`, if the note's state is 1 and the index is valid, it will call `realloc()` on the content pointer and the size, and then read in new content, then decrement the state. If the state is not 1, it will do nothing. This means that you can only edit a note once.
- In `show`, if the note's state is 1 and the index is valid, the name, size and state of the note will be displayed. This means that you can only show an unedited note.
- In `delete`, if the index is valid, the content chunk and the metadata chunk will be freed in that order. The pointers are also set to NULL.
## Vulnearabilities
**(1)** In the `read_input()` function, if the last byte is not `\n`, no null byte will be inserted. This leads to a leakage on uninitialized data.

**(2)** After creating, the content of a chunk is not cleared. This will lead to a leakage on a `fd` heap pointer in a fast chunk and a `main_arena` libc pointer in an unsorted chunk.

**(3)** The final subtle but critical vulnearability is based on how `malloc()` and `realloc()` works on size = 0:  `malloc()` returns a chunk in the 0x21 fastbin; while `realloc()` is exactly the same as `free()` when the pointer is valid and size = 0. This leads to a double free by using both the `edit` and `delete` functionalitites.

## Exploit plan

**Step 1:** Leak the heap address with vulnearabilities **(1)** and **(2)** using 2 consecutive fast chunks.

**Step 2:** Leak libc address using an unsorted chunk and a fast chunk (to prevent consolidate with top).

**Step 3:** Create a note of size 0, edit it and then delete it to achieve a double free. The double freed chunk will be in the 0x21 fastbin, which can't be used to overwrite `__malloc_hook` yet.

**Step 4:** Use that chunk to overwrite the content pointer of a note to a 0x71 fastbin chunk and its size to 0, use the same method to double free this chunk.

**Step 5:** Use this new double freed chunk to overwrite `__malloc_hook` with `one_gadget`.

**Step 6:** Make a call to `malloc()` and get shell.

## Full exploit
See `solve.py`.

# SMALLSERVICE
- Given files: `smallservice`, `client.py`.
- The binary has: `Partial RELRO`, `Canary found`, `NX enabled` and `No PIE`.
## Functionalities
- This program implements a small service which has the following functionalities: request a user, login, ping an IP and change password. We won't go deep into all of them because only 1 functionality is used to pwn this challenge.
- The `client.py` file gives us a nice and easy way to send payloads and communicate with the service.
- In `ping`, the program will first authenticate your user, if it is valid, then it will make a call to `inet_aton()` on the IP address and use `system()` to ping it.
## Vulnearabilities
**(1)** In `ping`, when authenticating with the `auth()` function, it will always return 1 or 2, which is both true, so you don't even need to be logged in as a valid user to ping.

**(2)** The `inet_aton()` function will return true as long as there is a valid IP address at the start of the string separated with the rest by a whitespace, so `127.0.0.1 ;/bin/sh;` is a valid IP address.

**(3)** The IP address will then be passed in to `system()` which will get us a shell.

## Exploit plan

**Step 1:** Edit the `client.py` file: changes the `self.r.recvuntil("\n\n\n")[:-3]` to one `self.r.recvline().strip()` and two `self.r.recvline()`s, or it won't work correctly.

**Step 2:** In `ping(self, host)`, replace `self.privatekey` with any string.

**Step 3:** Call `cl.ping("127.0.0.1 ;/bin/sh;")` and get shell.

## Full exploit
See `solve.py`.

# CALCCONV

- Given files: `CalcConv`.  
- The binary has: `Full RELRO`, `No canary found`, `NX enabled` and `PIE enabled`.  

## Functionalities  

- This program is where you can pass in commands in the form of `(<command>)` to choose between three functionalities: calculator, converter or setting.
- All the commands and outputs of this program is stored in a log file, which by default is `/tmp/debug.txt`.
- The program uses a self-calculated `canary` instead of a normal one.
- To use the program, first, you pass in a command in the form of `(<command>)` and then an expression for the corresponding command.
- In `calculator`, you can pass in a mathematical expression consists of 2 operands and 1 operator in +, -, *, /, %.
- In `convertor`, you can pass in a number followed by a currency unit.
- In `setting`, you can pass in a file name to change the path to the log file.

## Vulnearabilities  

**(1)** Unintended by the author: the canary is calculated using the address of the buffer containing `/dev/urandom` values instead of the values themselves, so we can calculate the canary if we can leak the stack address.

**(2)** We can use `setting` to set the log file to `/proc/self/fd/1` to display all the log on `stdout` (locally, `/dev/stdout` and `/dev/pts/0` work too, while on the server, only `/proc/self/fd/1` works, idk why).  This will get us a leakage on .text address and stack address.
  
**(3)** In the `get_input()` function, if the last byte is not `\n`, no null byte will be inserted. This is useful for leaking.

**(4)** In the `print_debug()` function, the buffer for the debug message is actually smaller than most of the debug messages' maximum size, this leads to a stack BOF.
  
## Exploit plan  
  
**Step 1:** Use `(setting)` to change the log file to `/proc/self/fd/1`.
  
**Step 2:** Leaking canary, there are 2 ways. The unintended way is to leak a stack address using the debug message and calculate it. The intended way is that the `command` in the `main_process()` function is right next to the canary, so if we can brute force a `)` character in the old RBP right after the canary (to make the program not crash at `strchr()`), then we can leak the canary in the debug message.
  
**Step 3:** Use `(calculator)`, leak .text address and stack address along the way, pass in a long expression without `\n` that concatenates with a libc address on the stack to leak libc.
  
**Step 4:**  Use `calculator()` again, this time pass in a command that contains `calculator()` and also a valid stack that can pass the canary check and then return to `one_gadget`, because we will pivot the stack to bss later.

**Step 5:** Because of the overflow in `print_debug()`, if we pass in an expression with size of 0x80, `remainder` will overwrite `canary`, `result` will overwrite old RBP. We pass in an expression so that the `canary` is the one that we leaked/calculated and the old RBP is on bss, where we set up the fake stack.

**Step 6:** From `print_debug()`, the program will return 2 times, so RSP will be pivotted into bss. Then, it will return to `one_gadget` and we get a shell.
  
 **Note 1:** The libc version is libc-2.27, which is not shown. But we can check by returning to `puts@PLT` instead of `one_gadget` and print out a libc address, then check with `libc-database`.
 
 **Note 2:** The call to `print_debug()` in `main()` can overflow more and is easier to manipulate, but it can't be use because the program only returns 1 time after that call, so we can't pivot the stack. Overwriting the return address with `one_gadget` also doesn't meet the constraints.
## Full exploit  

See `solve.py`.  
  
# BABY_ARM_SHELLCODE

- Given files: `babyshellcode`.  
- This binary is for `arm-32-little` and runs on a Ubuntu 18.04 system.
- The binary has: `Full RELRO`, `No canary found`, `NX enabled` and `PIE enabled`.  
- This is a very unique pwn + shellcode + linux system challenge.

## Functionalities  

- The program first `mmap()` a RWX region and then reads in 0x1000 bytes of input.
- It then prints out the higher 2 bytes of the mmapped region's address.
- After that, it `mmap()` another RWX region and then copies the built-in shellcode to the region, which will clear all the registers, then reads in another 0x48 bytes of input.
- After reading our shellcode, all the file descriptors `stdin`, `stdout` and `stderr` are closed.
- A seccomp rule is then defined, which will block all calls to syscall number -10181, 192 and 125, which are `__PNR_mmap`, `mmap2` and `mprotect`.
- Finally, the shellcode in the second region will be executed.

## Vulnearabilities  

**(1)** The 0x48 bytes of shellcode in the second region is too short, so we have to find a way to execute the 0x1000 bytes of shellcode in the other region. The intended way to do this is to write a specific piece of shellcode called the `egg hunter` to hunt for the first page and jump to it. Here, because the leak was 2 higher bytes of the address, we actually can bruteforce 4 bits of address to jump into the correct page.

**(2)** All file descriptors are closed, so we will have to make a call to `connect()` in our shellcode to backconnect to our server.
  
**(3)** All the `mmap()` and `mprotect()` syscalls are blocked, so we can't run anymore process other than our current one. This means we can't `execve()` any file, in other words, we can only interact with everything through our shellcode.

**(4)** Using the shellcode to investigate more about the server, we will find more interesting things.
  
## Exploit plan  
  
**Step 1:** In the second page, we used a `mov` and a `bx` instruction to bruteforce the first page address and jump to it (again, the better way is to use `egg hunter`).
  
**Step 2:** In the second page, we make a call to `connect()` to backconnect to our server.
  
**Step 3:** Then we make a call to `open()`, `read()` and `write()`, to read files and send output to our server. Reading the `/flag` file shows that we don't have the permission to read it. (File-reading shellcode can be found in `read_file.py`.)
  
**Step 4:**  Changing the shellcode to `open()` a directory and `getdents()` to list all the files in the opened directory and investigate around the server, we found another user `babyfmt` that has its own directory, its own binary and its own flag, it also shows that `/flag` is just a symbolic link. (Dir-listing shellcode can be found in `dir_list.py`.)

**Step 5:** Changing the shellcode to `getlink()` on `/flag`, we know that it is a symlink to `/home/babyfmt/flag`. So this means we somehow have to gain `babyfmt` privilege to read this file.

**Step 6:** Using the file-reading code again, we can dump the `babyfmt` binary.
  
**Step 7:** The suspection now is that the server run another service for `babyfmt` and we can get the flag through that service. Port scanning result in another opened port: 8888. (`babyshellcode` is at port 9999.)

**Step 8:** Connecting to port 8888 from our machine doesn't work. The suspection now is that the port is only opened locally, so we have to make another call to `connect()` in our shellcode to `localhost` at port `8888`, and it works this time. This means that we have to exploit the `babyfmt` file through our shellcode to get the flag. (Although the final hint shows that checking the files in `/etc/xinetd.d/` is a better way to get all these informations.)
## About BABYFMT
- The binary has: `Full RELRO`, `No canary found`, `NX enabled` and `PIE enabled`.  
- It is a very simple program, first, it reads the flag and stores it in bss, then it goes into an infinite loop that reads our input and passes it directly to the fmt parameter of `printf()`, resulting in an infinite format string bug.
- We can exploit this by using the format `%34$x` to leak an address of .text (the number 34 is achieved by bruteforce dumping the stack), then we can calculate the flag's address and use the format `%s` to print out the flag.
- The challenging part here is that we have no pwntools to help us simplify this exploit, since everything has to be done through shellcode. My teammate `@pickaxe` coded this fabulous ARM assembly code to do all the calculating to get the flag.
## Full exploit  

See `solve.py` (`@pickaxe`'s code).  
  




