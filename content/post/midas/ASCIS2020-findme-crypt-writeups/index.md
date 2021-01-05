---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "[ASCIS2020 Quals] Findme, Crypt writeups"
subtitle: ""
summary: "Writeups for ASCIS/SVATTT2020 Quals reversing challenges"
authors: [midas]
tags: []
categories: []
date: 2020-11-06T05:56:39-08:00
lastmod: 2020-11-06T05:56:39-08:00
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

All files can be found [here](https://github.com/lkmidas/Short-CTF-Writeups/tree/master/ascis2020_re).

# FINDME
- Given files: `findme.exe`.
- The given file is a normal Windows 32-bit PE file which reads in and checks a password.
## Analysis

### Step 1: Static analysis (IDA Pro)
First off, I started to analyze the file statically. By looking at the `main` function, it is clear that this program reads an input password, then passes it to the checking function using the **Remote procedure call** (RPC) protocol, I knew this because the program makes calls to `RpcStringBindingComposeA`, `RpcBindingFromStringBindingA` and `NdrClientCall2` (although at the time, I knew nothing about RPC). 

By reading the documentation from Microsoft about RPC and also doing some googling, I knew that this is a server - client protocol, and our program is acting as a client (RPC is always initiated by the client). Therefore, there must be a server running somewhere, but I couldn't find the part where the program initiates the server in `main`.

### Step 2: Getting the server dll (IDA Pro)
Initially, my suspect was that the server is initiated somewhere before `main`, in the `init` process of the PE. But I thought that looking into it would cost too much time, so I went the easier way, which is using the debugger attach option of IDA to list all the processes running in the system, and I found out that there was a dll running in the `%TEMP%` folder of Windows, and this probably was the server (I renamed it too `server.dll`).

### Step 3: Static analyzing the server (IDA Pro)
I opened up the dll in IDA, there is a lot of functions, and most of the calls are (maybe) obfuscated in the way that they are called indirectly by some pointers in the data segment. Again, the client passes the password to the server using `NdrClientCall2`, one of the parameter of that function is a *MIDL-generated procedure format string*, which indicates what function will be called in the server. I did some googling to try and understand this parameter, but I didn't find much information, so I just looked at all the functions in the server dll one by one, and the most interesting function is the first function `sub_401000`, which only takes in 1 parameter and passes it to a lot of bitwise equations and finally returns a boolean value, and that seems likely to be the password checking function. 

### Step 4: Solving the equations (z3)
So then, I simply wrote a python script to solve the equations using `z3`, the checking process is pretty simple: it checks if the length of the password is 16, and then do a series of calculations that form 16 equations. The script is as follow:
```
from z3 import BitVec, Solver

a = []
for i in range(16):
	a.append(BitVec('a' + str(i), 8))

s = Solver()

v1 = a[14]
v32 = a[12]
v31 = v1
v2 = a[15] ^ v1
v3 = a[13]
v4 = v3 ^ v2
v5 = a[6]
v6 = v32 ^ v3 ^ v2
v33 = a[10]
v35 = a[11]
v43 = a[9]
v44 = a[8]
v34 = a[5]
v42 = a[4]
v29 = v32 ^ v2
v40 = a[1]
v41 = a[0]
v38 = a[3]
v36 = a[2]
v24 = v43 ^ v40 ^ v36 ^ v32 ^ v2
v37 = a[7]
v25 = v43 ^ a[0] ^ v33 ^ v5 ^ v37 ^ v3 ^ v35
v26 = v44 ^ v42 ^ v40 ^ a[0] ^ v37 ^ v3 ^ v35
v30 = a[15] ^ v32
v39 = v3 ^ v32 ^ v35
v27 = v43 ^ v44 ^ a[0] ^ v36 ^ v37 ^ v3 ^ v2
v28 = v31 ^ v3 ^ v32 ^ v35 ^ v44 ^ v42 ^ a[0] ^ v33 ^ v36
s.add((v35 ^ (v43 ^ v34 ^ v40 ^ a[0] ^ v33 ^ v5 ^ v38 ^ v36 ^ v2)) == 117)
v8 = 0
s.add((v35 ^ (v43 ^ v44 ^ v34 ^ v42 ^ v40 ^ a[0] ^ v6)) == 49)
s.add((v44 ^ (v34 ^ v42 ^ v5 ^ v38 ^ v37 ^ v6)) == 82)
v10 = 0
s.add((v35 ^ (v43 ^ v44 ^ v34 ^ v40 ^ v41 ^ v33 ^ v4)) == 102)
v12 = a[6]
s.add((v35 ^ (v43 ^ v34 ^ v42 ^ v40 ^ v38 ^ v36 ^ v30)) == 115)
v13 = 0
s.add((v44 ^ (v42 ^ v41 ^ v12 ^ v38 ^ v36 ^ v29)) == 56)
s.add(v28 == 50)
s.add((v42 ^ (v33 ^ v12 ^ v38 ^ v36 ^ v39)) == 110)
v16 = 0
s.add(v27 == 7)
v17 = 0
s.add((v31 ^ (v32 ^ v35 ^ v42 ^ v41 ^ v33 ^ v12 ^ v36)) == 7)
s.add(v26 == 16)
v19 = 0
s.add((v43 ^ (v44 ^ v41 ^ v37 ^ v39)) == 29)
s.add(v25 == 7)
v21 = 0
s.add(((v43 ^ (v34 ^ v42 ^ v38 ^ v30)) == 25))
s.add(v24 == 78)
s.add((v31 ^ (v34 ^ v40 ^ v38 ^ v37)) == 48)

s.check()
ans = s.model()
result = ''
for i in range(16):
	result += chr(ans[a[i]].as_long())
print result
```
The password is ``HkX~^=`asfWY^&y<``. Simply enter it into the client and get the flag: `ASCIS{pl4y1ng_wi1h_RPC_i5_v3ry_4un}`

# CRYPT
- Given files: `Crypt`, `encrypted.bin`.
- The `Crypt` file is an ELF 64-bit executable compiled from C++ which takes 2 command line arguments: a key and a file name. It will check if the key is correct and then use it to somehow encrypt the file and generate `encrypted.bin`.
- The given `encrypted.bin` is the encrypted flag file, we have to reverse engineer the ELF file to find a way to decrypt this.
## Analysis

### Step 1: Static analysis: deobfuscating (IDA Pro)
First off, I started to analyze the file statically. The first thing that happened when I threw the program into IDA is that there were a bunch of errors about PLT. Skipping all those errors and looking into the file, it's obvious that all the library calls through PLT are obfuscated. The obfuscation scheme is not that difficult: the program has a table of all the pointers to the library functions (the same as GOT), and when it calls a library function, it makes some calls to some functions that literally get an offset from the start of that table to the desired function pointer. Therefore, it's not that hard to statically renamed all of the obfuscated library calls.

### Step 2: Retrieving the key (IDA Pro + GDB)
The comparison happens in the if statement using only 1 function `sub_45AE`, so using ANGR to try to solve the key is not a viable strategy (I did try it and failed horribly). Looking back up, I saw that three C++ strings were constructed, one from our input key, and two from the global variables `unk_9A80` and `unk_9AA0`. The values of these two variables are initialized somewhere in the initialization of the process and can be found by cross-referencing them, but they are really not that important because I decided to do this part dynamically anyway.

So, looking more carefully, our key and `unk_9AA0` go through a function `sub_411A`, by debugging, it's easy to recognize that this function simply mirror the string. The other variable `unk_9A80` in the other hand, goes through a series of function and then gets passed in to a final function `sub_47CC` together with our mirrored input key. 

About that "series of functions", I didn't even reverse them statically and just found the resulting string by debugging, it was `3669372743793841`.

About `sub_47CC`, it literally is just an addition function on two strings that represent large integers, where the leftmost digit being the least significant digit (that is why our strings are mirrored). The value of `unk_9AA0` after mirroring is `2333602996074364`. So in the end, all the key checking part does is to check if our input key satisfies this equation: `1483973472739663 + key == 4634706992063332`. Therefore, the key can be found very easily: `3150733519323669`.

### Step 3: Decrypt the encrypted file (IDA Pro + PyCrypto)
After the key comparison is a bunch of C++ allocators and strings garbage that I simply just ignored. The important encryption function is under the for loop, function `sub_34C8`. Digging deep into this function, it is quite a complicated cryptographic function, so I looked for constants to find out if it is any of the popular crypto. I found an interesting array of constants `byte_9020`, which after some quick googling, I knew that this is called the `AES Sbox`. So this is for sure an AES encryption, the problem then was to know which AES mode it is, and what is the AES key.

About the key, it was just the matter of debugging with GDB again and dumping it out, which was ``P4nd`p<c8gE;T$F8``.

About the mode, I tried to create a file contains all character `a`, and encrypted it with the program. The result is that the encrypted file contains a bunch of the same blocks. I asked my team crypto player `@pcback` which mode of AES it is that makes the same cipher blocks for the same plain content, and he said it is **AES ECB**. With all the information, I just wrote a quick python script to decrypt the given encrypted file, which turns out to be a PNG image of the flag. The script is as follow:
```
import base64
from Crypto.Cipher import AES
from Crypto import Random


key = b"P4nd`p<c8gE;T$F8"
encrypt = open("./encrypted.bin", "rb").read()
cipher = AES.new(key, AES.MODE_ECB)
open("out.png","wb").write(cipher.decrypt(encrypt))
```
The flag is `ASCIS{C4yp1o_1s_5impl3_b4t_C++_i5_cr4z9}`.
