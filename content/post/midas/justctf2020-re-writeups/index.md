---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "justCTF2020[*] - debug_me_if_you_can, REmap writeups"
subtitle: ""
summary: "Writeups for justCTF2020[*] reversing challenges"
authors: [midas]
tags: []
categories: []
date: 2021-02-01T10:03:59+07:00
lastmod: 2021-02-01T10:03:59+07:00
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
**This post is mirrored from its [original post at my blog](https://lkmidas.github.io/posts/justctf2020_writeups/), some texts/links here maybe broken.**

{{< toc >}}

{{% callout %}}
*Use the table of contents on the right to navigate to the challenge that you are interested in.*
{{% /callout %}}

***

## debug_me_if_you_can
### Introduction
{{% callout %}}
- **Given files:** [supervisor](debug_me/supervisor), [crackme.enc](debug_me/crackme.enc), [flag.png.enc](debug_me/flag.png.enc).
- **Description:** `I bet you can't crack this binary protected with my custom bl33d1ng edg3 pr0t3c70r!!!111oneoneone`
- **Category:** Reverse engineering
- **Summary:** An anti-debug type challenge, with a process forks a child then monitors it with `ptrace()`. The child process is encrypted, and only being decoded to execution after sending debug trap to the parent. Our job is to find out what the child does to decrypt the encrypted flag image.
{{% /callout %}}

{{% callout %}}
1. Analyze [supervisor](debug_me/supervisor) -> Learn that it forks a child process which executes [crackme.enc](debug_me/crackme.enc) and monitors it with `ptrace()`.
2. Analyze the parent process -> Learn that it catches debug break and modifies the code of its child on the fly.
3. Use `LD_PRELOAD` hooking technique to see what code is being modified in the child -> Patch it accordingly.
4. Analyze the child process -> Learn that it checks `secret_key` by simple math and comparison.
5. Write code to generate correct key -> get flag.
{{% /callout %}}

### Analyze the supervisor
The [supervisor](debug_me/supervisor) seems like a good place to start, so I started looking at it first. It is clear that it initializes a lot of data, then `fork()` a child process. The child process will then make a call to `ptrace()` with `PTRACE_TRACEME`, then execute [crackme.enc](debug_me/crackme.enc) via `execl`. To this point, I already knew that this is a `Nanomites` type challenge that makes it hard for us to debug the child process, which is where all the main logics are.

{{% callout %}}
*Nanomites is an anti-debug software protection technique. Resource for further information: [Nanomites on Linux](https://malwareandstuff.com/nanomites-on-linux/)*
{{% /callout %}}

### Analyze the parent process
The parent process is interacting with its child by catching debug break `0xCC`, then modify its code to execute. I didn't reverse engineer the whole part of how it modifies the child process, I only tried to have a high-level overview of what's going on. The reason is that I already thought of using the `LD_PRELOAD` hooking technique that is super useful against `Nanomites`. In short, this is what the parent does:
1. Catch debug break `0xCC`.
2. Check if the next 4 bytes are `0x1337BABE`.
3. Look for the first 4 bytes of `0xFEEDC0DE` after that.
4. Look for the first 4 bytes of `0xDEADC0DE` after that.
5. Decrypt the code between the 2 positions in (3) and (4).
6. Set the child `RIP` using `PTRACE_SETREGS`.
7. At the end of the decrypted code will be another `0xCC`, therefore it will re-encrypt the code when the function returns.

It modifies the child's code by using `ptrace()` with `PTRACE_POKETEXT`. The code is decrypted using the data it reads from the child using `PTRACE_PEEKTEXT` and the data that it initilized back at `main()`. The data go through a bunch of bitwise operations, which I had no intent to see what it does since I can hook `ptrace()` and dump these values out.

### Hooking ptrace with LD_PRELOAD
This is a well-known technique for dealing with `Nanomites`, as introduced [here](https://tbrindus.ca/correct-ld-preload-hooking-libc/). Since it is `ptrace()` with `PTRACE_POKETEXT` and `PTRACE_SETREGS` that we are intrested in, I decided to hook exactly those 2:
```C
long int ptrace(enum __ptrace_request __request, ...){
    pid_t caller = getpid();
    va_list list;
    va_start(list, __request);
    pid_t pid = va_arg(list, pid_t);
    void* addr = va_arg(list, void*);
    void* data = va_arg(list, void*);
    long int (*orig_ptrace)(enum __ptrace_request __request, pid_t pid, void *addr, void *data);
    orig_ptrace = dlsym(RTLD_NEXT, "ptrace");
    long int result = orig_ptrace(__request, pid, addr, data);
    if (__request == PTRACE_SETREGS){
        unsigned long rip = *((unsigned long*)data + 16);
        printf("SETREGS: rip: 0x%lx\n", rip);  
    } else if (__request == PTRACE_POKETEXT){
        printf("POKETEXT: (addr , data) = (0x%lx , 0x%lx)\n", (unsigned long)addr - 0x555555554000, (unsigned long)data);
    }
    return result;
}
```

Compile the lib:
```bash
gcc -shared -fPIC -ldl ptrace_hook.c -o ptrace_hook.so
```

I then wrote a short `python` script to run the binary using `pwntools`. The reason I used `pwntools` is to easily disable `ASLR`, so that I can calculate the offset to the modified code by simply subtracting `0x555555554000` (as seen in the code above):
```python
from pwn import *
r = process("./supervisor", env={"LD_PRELOAD":"./ptrace_hook.so"}, aslr=False)
r.interactive()
```

Here is what I initially got:
```bash
POKETEXT: (addr , data) = (0x1800 , 0x45c748fffff84be8)
POKETEXT: (addr , data) = (0x1871 , 0x89e0458b48000000)
POKETEXT: (addr , data) = (0x18e5 , 0x1ebfffff7b5e8c7)
POKETEXT: (addr , data) = (0x1838 , 0x8948d8458b48c289)
POKETEXT: (addr , data) = (0x18a8 , 0x775fff883fffffd)
SETREGS: rip: 0x17f9
Hello there!
POKETEXT: (addr , data) = (0x16db , 0xe8c78948000009ab)
POKETEXT: (addr , data) = (0x174b , 0x8348008b48d8458b)
POKETEXT: (addr , data) = (0x17bd , 0x1ebfffff93de8c7)
POKETEXT: (addr , data) = (0x1712 , 0xe8c7894800000000)
POKETEXT: (addr , data) = (0x1781 , 0xf975e8c78948f845)
SETREGS: rip: 0x16d4
Error! https://www.youtube.com/watch?v=Khk6SEQ-K-k
0xCCya!
```

We can see that there are 2 code blocks that are being modified by running it like this, let's investigate the child process further.

### Analyze the child process
First thing I do is to write a simple `IDA` script to patch the child's memory (I know my code is ugly, but it's just for CTF and it works):
```python
import ida_bytes

patches_1 = [
    (0x1800 , 0x45c748fffff84be8),
    (0x1871 , 0x89e0458b48000000),
    (0x18e5 , 0x1ebfffff7b5e8c7),
    (0x1838 , 0x8948d8458b48c289),
    (0x18a8 , 0x775fff883fffffd)
]

patches_2 = [
    (0x16db , 0xe8c78948000009ab),
    (0x174b , 0x8348008b48d8458b),
    (0x17bd , 0x1ebfffff93de8c7),
    (0x1712 , 0xe8c7894800000000),
    (0x1781 , 0xf975e8c78948f845)
]

# Patch the irrelevant 0xCC bytes
rip = [0x17f9, 0x16d4]
CC = [0x17dc, 0x16b7]

for i in range(len(rip)):
    ida_bytes.patch_bytes(CC[i], '\x90'*(rip[i] - CC[i])

# Patch the encrypted bytes
def patch(patches):
    for i in patches:
        print(hex(i[0]))
        ida_bytes.patch_qword(i[0], i[1])

patch(patches_1)
patch(patches_2)
```

One thing to note here is that I also patched the part from the `0xCC` to where the child's `RIP` is set to `NOPs`, this helps IDA decompiler from stucking at `__debugbreak()`. 

After patching and decompiling, it can be easily seen that the process tries to read from a file named `secret_key`. I didn't have that file yet, that's why it only decrypts 2 short blocks of code. Adding a file named `secret_key` with some dummy contents inside, then re-running the program will reveal more code blocks that are decrypted. Simply applying the exact same patching strategy as above, I could construct the full checking routine in the child (check the full patching code at [patch.py](debug_me/patch.py)).

{{% callout %}}
*As I have mentioned above, when each decrypted code block returns, the parent will try to re-encrypt the code. Therefore, we only need to apply the patch for the FIRST appearance of each address, and ignore all the subsequent ones.*
{{% /callout %}}

### Calculating the correct key
The function for checking the key:
```C
__int64 __fastcall check_key(__int64 key, unsigned __int64 size)
{
  int v2; // eax
  char v4; // [rsp+1Fh] [rbp-11h]
  int j; // [rsp+20h] [rbp-10h]
  unsigned int i; // [rsp+24h] [rbp-Ch]
  int index; // [rsp+28h] [rbp-8h]
  unsigned int correct; // [rsp+2Ch] [rbp-4h]

  correct = 1;
  index = 0;
  for ( i = 1; i <= 0x7F; ++i )
  {
    for ( j = 0; ; j = calculate(j, 2, 2) )
    {
      while ( 1 )
      {
        if ( size <= index )
        {
          correct = -1;
          goto LABEL_13;
        }
        v2 = index++;
        v4 = *(_BYTE *)(v2 + key);
        if ( (unsigned int)compare_char((unsigned int)v4, '0') != 1 )
          break;
        j = calculate(j, 2, 1);
      }
      if ( (unsigned int)compare_char((unsigned int)v4, '1') != 1 )
        break;
    }
    if ( (unsigned int)compare_char((unsigned int)v4, '?') == 1 )
    {
      if ( i != ARR[j] )
        correct = -1;
    }
    else
    {
      correct = -1;
    }
LABEL_13:
    if ( correct == -1 )
      break;
  }
  if ( size != index + 1 )
    correct = -1;
  return correct;
}
```

Fortunately, the checking is not that complicated. What it does is by iterating `i` from 1 to 127 in the outer loop, then iterate through each of the characters in our `secret_key` file. The variable `j` starts from 0, then for each character `0` in our key, we have `j = 2*j + 1`, and for each character `1`, we have `j = j*2 + 2`. Finally, when it reaches the character `?`, it checks in a constant array `ARR` to see if `ARR[j] == i`. So essentially, we have to write a key which contains 128 small blocks of 0s and 1s that calculate the correct index `j` in `ARR` where each `i` appears.

The algorithm to calculate the key for any number `j` is by simply starting from `j` then iterates back to 0:
```python
def get_key(n):
    key = ""
    while (n != 0):
        if n & 1:
            key += "0"
            n = (n - 1) // 2
        else:
            key += "1"
            n = (n - 2) // 2
    return key[::-1]
```

Then we can calculate all `j` for all `i`:
``` python
secret_key = ""
for i in range(1, 128):
    x = ARR.index(i)
    secret_key += get_key(x) + '?'
```

However, using the `secret_key` above still yields incorrect result. This is the weirdest part of the challenge, looking back at the checking code, we can see one more comparison at the end: `size != index + 1`. This means there is one more character at the end of the key. I suspected that character would be a null `\0` or a line break `\n` and tried them both out. The line break `\n` gave me the correct key, the program then simply decrypts `flag.png.enc` and nicely gives us `flag_decoded.png`. It is a blessing we don't have to do the patching for the decoding routine, since the key is enough for us to get the flag.

And that was it, ***first blood for Efiens***:
```
justCTF{Cr4ckm3s_are_0xCCiting}
```

### Appendix
The source for `ptrace()` hooking library is [ptrace_hook.c](debug_me/ptrace_hook.c).

The script to run with `LD_PRELOAD` is [run.py](debug_me/run.py).

The script to patch the child is [patch.py](debug_me/check.py).

The script to calculate the key is [a.py](debug_me/a.py).

***

## REmap
### Introduction
{{% callout %}}
- **Given files:** [backup_decryptor.exe](REMap/backup_decryptor.exe).
- **Description:** `Recently we fired our admin responsible for backups. We have the program he wrote to decrypt those backups, but apparently it's password protected. He did not leave any passwords and he's not answering his phone. Help us crack this password!`
- **Category:** Reverse engineering
- **Summary:** The executable given in this challenge is generated using `PyInstaller`. However, the python interpreter of it is a modified version with all opcodes shuffled together. Our goal is to first find a way to remap the new opcodes to the old ones so as to successfully decompile the python compiled code.
{{% /callout %}}

{{% callout %}}
1. Extrace `PyInstaller` packed executable with [pyinstxtractor.py](https://github.com/extremecoders-re/pyinstxtractor) -> See entry point at `backup_decryptor.pyc`.
2. Try to decompile/disassemble it -> Fail because of invalid arg count.
3. Recognize that it has remapped all the python opcodes -> Find a way to find the mapping back to the original.
4. Write code to convert the mapped `pyc` to the original -> Decompile it.
5. Analyze the decompiled python code -> Get flag.
{{% /callout %}}

### Extracting the executable
Initially, I threw the executable into IDA, it's a huge binary, and I saw an interesting string `_MEIPASS2`. Googling this string reveals that this is an exe generated by [PyInstaller](https://www.pyinstaller.org/), which is generated from python code. An easy way to extract this is to use the [pyinstxtractor.py](https://github.com/extremecoders-re/pyinstxtractor), here is the result:
```bash
[+] Processing backup_decryptor.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 38
[+] Length of package: 5598412 bytes
[+] Found 31 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: backup_decryptor.pyc
[+] Found 222 files in PYZ archive
[+] Successfully extracted pyinstaller archive: backup_decryptor.exe

You can now use a python decompiler on the pyc files within the extracted directory
```

As you can see, it extracts the executable into a folder, which contains the python interpreter `python38.dll` itself, and a bunch of python compiled code `pyc` files. Out of the 3 possible entry points that it found, it is almost 100% sure that the real entry point is `backup_decryptor.pyc`. Since `pyc` files are just python bytecodes, we need a way to decompile/disassemble them. I tried out the 2 popular python decompiler, which are [uncompyle6](https://pypi.org/project/uncompyle6/) and [decompyle3](https://github.com/rocky/python-decompile3), but both of them didn't succeed in doing so. I struggling for a while, then decided to disassemble it first instead of decompiling using python's built-in `dis` package, but it fails as well! All the failure was due to invalid argument count for an opcode. I actually got frustrated a lot and tried out a lot of different methods to decompile it, but all fails.

### Remapping the python opcodes
A while after, I decided to open the `pyc` file in a hex editor, and compare it with a normal test `pyc` generated by myself. What I found is that the first few opcodes of the 2 are different (typically the first few opcodes of all `pyc` files are the same). Looking back at the challenge's name, I finally recognized that this python interpreter is a custom one, and the opcodes value have been shuffled around. This is a kinda well-known technique to obfuscate python executables, as explained quite detailed [here](https://medium.com/tenable-techblog/remapping-python-opcodes-67d79586bfd5). So the goal now is to find a mapping back to the original opcodes from the modified ones, there are 3 approaches that I had thought of:
1. Copy the modified `python38.dll` interpreter into my own python folder and run it, then use the `opcode` package to get the info.
2. Diffing the modified interpreter with the original one to find out the different opcodes.
3. Using all the extracted `pyc` files and try to look for a way to map back from there.

For (1), I have no idea how to run with the modified `python38.dll`, my python crashes everytime I tried to do it, so it was a fail. For (2), I'm a noob and not used to binary diffing, so I had no idea how to do it. Therefore, I had to resort to option (3), which is kind of a pain. What I did was to investigate the `opcode.pyc` file in the extracted folder that I renamed to `opcode_mapped.pyc`, and a compiled version of the original `opcode.py`, which I named `opcode_orig.pyc`. I found out that most of the opcodes are saved as constants in the file, in a contiguous array in the form of: `name1 -> opcode1 -> name2 -> opcode2 -> ...`. Therefore, I wrote a short piece of code to parse them out:
```python
orig = {'POP_TOP': 1, 'ROT_TWO': 2, 'ROT_THREE': 3, 'DUP_TOP': 4, 'DUP_TOP_TWO': 5, 'ROT_FOUR': 6, 'NOP': 9, 'UNARY_POSITIVE': 10, 'UNARY_NEGATIVE': 11, 'UNARY_NOT': 12, 'UNARY_INVERT': 15, 'BINARY_MATRIX_MULTIPLY': 16, 'INPLACE_MATRIX_MULTIPLY': 17, 'BINARY_POWER': 19, 'BINARY_MULTIPLY': 20, 'BINARY_MODULO': 22, 'BINARY_ADD': 23, 'BINARY_SUBTRACT': 24, 'BINARY_SUBSCR': 25, 'BINARY_FLOOR_DIVIDE': 26, 'BINARY_TRUE_DIVIDE': 27, 'INPLACE_FLOOR_DIVIDE': 28, 'INPLACE_TRUE_DIVIDE': 29, 'GET_AITER': 50, 'GET_ANEXT': 51, 'BEFORE_ASYNC_WITH': 52, 'BEGIN_FINALLY': 53, 'END_ASYNC_FOR': 54, 'INPLACE_ADD': 55, 'INPLACE_SUBTRACT': 56, 'INPLACE_MULTIPLY': 57, 'INPLACE_MODULO': 59, 'STORE_SUBSCR': 60, 'DELETE_SUBSCR': 61, 'BINARY_LSHIFT': 62, 'BINARY_RSHIFT': 63, 'BINARY_AND': 64, 'BINARY_XOR': 65, 'BINARY_OR': 66, 'INPLACE_POWER': 67, 'GET_ITER': 68, 'GET_YIELD_FROM_ITER': 69, 'PRINT_EXPR': 70, 'LOAD_BUILD_CLASS': 71, 'YIELD_FROM': 72, 'GET_AWAITABLE': 73, 'INPLACE_LSHIFT': 75, 'INPLACE_RSHIFT': 76, 'INPLACE_AND': 77, 'INPLACE_XOR': 78, 'INPLACE_OR': 79, 'WITH_CLEANUP_START': 81, 'WITH_CLEANUP_FINISH': 82, 'RETURN_VALUE': 83, 'IMPORT_STAR': 84, 'SETUP_ANNOTATIONS': 85, 'YIELD_VALUE': 86, 'POP_BLOCK': 87, 'END_FINALLY': 88, 'POP_EXCEPT': 89, 'STORE_NAME': 90, 'DELETE_NAME': 91, 'UNPACK_SEQUENCE': 92, 'FOR_ITER': 93, 'UNPACK_EX': 94, 'STORE_ATTR': 95, 'DELETE_ATTR': 96, 'STORE_GLOBAL': 97, 'DELETE_GLOBAL': 98, 'LOAD_CONST': 100, 'LOAD_NAME': 101, 'BUILD_TUPLE': 102, 'BUILD_LIST': 103, 'BUILD_SET': 104, 'BUILD_MAP': 105, 'LOAD_ATTR': 106, 'COMPARE_OP': 107, 'IMPORT_NAME': 108, 'IMPORT_FROM': 109, 'JUMP_FORWARD': 110, 'JUMP_IF_FALSE_OR_POP': 111, 'JUMP_IF_TRUE_OR_POP': 112, 'JUMP_ABSOLUTE': 113, 'POP_JUMP_IF_FALSE': 114, 'POP_JUMP_IF_TRUE': 115, 'LOAD_GLOBAL': 116, 'SETUP_FINALLY': 122, 'LOAD_FAST': 124, 'STORE_FAST': 125, 'DELETE_FAST': 126, 'RAISE_VARARGS': 130, 'CALL_FUNCTION': 131, 'MAKE_FUNCTION': 132, 'BUILD_SLICE': 133, 'LOAD_CLOSURE': 135, 'LOAD_DEREF': 136, 'STORE_DEREF': 137, 'DELETE_DEREF': 138, 'CALL_FUNCTION_KW': 141, 'CALL_FUNCTION_EX': 142, 'SETUP_WITH': 143, 'LIST_APPEND': 145, 'SET_ADD': 146, 'MAP_ADD': 147, 'LOAD_CLASSDEREF': 148, 'EXTENDED_ARG': 144, 'BUILD_LIST_UNPACK': 149, 'BUILD_MAP_UNPACK': 150, 'BUILD_MAP_UNPACK_WITH_CALL': 151, 'BUILD_TUPLE_UNPACK': 152, 'BUILD_SET_UNPACK': 153, 'SETUP_ASYNC_WITH': 154, 'FORMAT_VALUE': 155, 'BUILD_CONST_KEY_MAP': 156, 'BUILD_STRING': 157, 'BUILD_TUPLE_UNPACK_WITH_CALL': 158, 'LOAD_METHOD': 160, 'CALL_METHOD': 161, 'CALL_FINALLY': 162, 'POP_FINALLY': 163}

moded = {}
mapping = {}

with open('./opcode_mapped.pyc', 'rb') as f:
    modded_opcode_pyc = f.read()

for instr in orig:
    i = instr.encode()
    off = modded_opcode_pyc.find(i) + len(i) + 1
    new_opcode = modded_opcode_pyc[off]
    moded[i.decode("utf-8")] = new_opcode
    modded_opcode_pyc = modded_opcode_pyc[off:]

for instr in orig:
    mapping[moded[instr]] = orig[instr]
```

Running this gave me a mapping that looks decent, so I decided to try using it to convert the `pyc` back to the original opcodes.

### Converting modified code back
This conversion requires a bit of knowledge about how python compiled code files are formed. The link I provided above about python opcode remapping did a pretty good job at explaining. Here are a few key points:
- The `pyc` file contains a header with magic bytes and timestamp, then after that comes one or more `code_object`.
- Each `code_object` contains its code in `co_code`, and its constants in `co_consts`.
- Each `code_object.co_consts` can contain reference to another `code_object`, this make conversion a recursive process.

So the conversion can be written as follows:
```python
def convert_code(co_code, mapping):
    new_co_code = b""
    for i in range(0, len(co_code)):
        if i & 1:
            new_co_code += p8(co_code[i])
        else:
            if co_code[i] in mapping:
                new_co_code += p8(mapping[co_code[i]])
            else:
                new_co_code += p8(co_code[i])
    return new_co_code

def recurse_convert_all(code_obj, mapping):
    new_co_code = convert_code(code_obj.co_code, mapping)
    new_co_consts = []
    for const in code_obj.co_consts:
        if type(const) == types.CodeType:
            new_const = recurse_convert_all(const, mapping)
            new_co_consts.append(new_const)
        else:
            new_co_consts.append(const)
    
    new_code_obj = code_obj.replace(co_code=new_co_code, co_consts=tuple(new_co_consts))
    return new_code_obj
```

Note that in python 3.8, all python opcodes are 2 bytes long, even if it has no operands. That makes converting very easy, since we can just map the opcodes and keep the operands as they are. 

Using this code, I successfully converted the main `code_object` of `backup_decryptor.pyc`. However, the code sadly still cannot be disassembled. It can be disassembled a lot more than before, but still error at some point due to the same error. I then tried to convert `opcode_mapped.pyc` back to find if there are any errors in my mapping. Turns out there are some errors: 2 opcodes are not placed in the memory the way I declared above, I simply hard-coded them to correct the issue:
```python
moded["EXTENDED_ARG"] = 109
moded["LOAD_METHOD"] = 90
```

Then finally I could have a fully-converted file:
```python
final = recurse_convert_all(code_object, mapping)

with open('backup_decryptor_converted.pyc', 'wb') as fc:
    fc.write(b"\x55\x0d\x0d\x0a" + b"\0"*12) # header
    marshal.dump(final, fc)
```

### Analyzing decompiled python code
With this clean python compiled code, I could decompile it with `decompyle3` successfully. The resulting python file is small, but still has a layer of obfuscation.

The obfuscation is not that hard though: all the strings in the file are decrypted from a list of bytes using several bit-wise functions, and all the built-in function calls in the file are retrieved by `getattr()` from `builtins`. But since this is python code, we can even ignore how these functions decrypt the strings, and just use `print()` to print out all the resulting strings. Below is the code after replacing all the decrypted strings and functions:
```python
import builtins as bi

def sc(s1, s2):
    if len(s1) != len(s2):
        return False
    res = 0
    for x, y in zip(s1, s2):
        res |= ord(x) ^ ord(y)
    else:
        return res == 0

f = input("Enter password:")

if f.startswith("justCTF{") and f.endswith("}"):
    ff = f[8:-1]
    rrr = True
    if len(ff) == 0:
        rrr = False
    if not sc("b3", ff[0:2] if ff[0:2] != '' else 'c1'):
        rrr = False
    if not sc("77", ff[2:4] if ff[2:4] != '' else 'kl'):
        rrr = False
    if not sc("3r", ff[4:6] if ff[4:6] != '' else '_f'):
        rrr = False
    if not sc("_r", ff[6:8] if ff[6:8] != '' else '7f'):
        rrr = False
    if not sc("3h", ff[8:10] if ff[8:10] != '' else 'd0'):
        rrr = False
    if not sc("1r", ff[10:12] if ff[10:12] != '' else '_a'):
        rrr = False
    if not sc("3_", ff[12:14] if ff[12:14] != '' else 'jk'):
        rrr = False
    if not sc("7h", ff[14:16] if ff[14:16] != '' else '8k'):
        rrr = False
    if not sc("15", ff[16:18] if ff[16:18] != '' else '5b'):
        rrr = False
    if not sc("_6", ff[18:20] if ff[18:20] != '' else '_9'):
        rrr = False
    if not sc("uy", ff[20:22] if ff[20:22] != '' else 'xd'):
        rrr = False
    
    print()
    if rrr:
        print("Even tho the password is correct, fuck you, I removed the rest of the code. You shouldn't have fire me.")
    else:
        print("Nope")
else:
    print("Nope")
```

The function `sc()` is just a string comparison, so essentially, all the comparisons will be true if the corresponding part of the flag equals to the first parameter. Concatenating them together gives me the flag:
```
justCTF{b3773r_r3h1r3_7h15_6uy}
```

### Appendix
The script to remap python compiled code is [remap.py](REmap/remap.py).
