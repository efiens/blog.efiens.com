---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "SVATTT 2019 Quals 0day Hunter"
subtitle: ""
summary: ""
authors: [luibo]
tags: []
categories: []
date: 2019-11-04T21:55:47+07:00
lastmod: 2019-11-04T21:55:47+07:00
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

On 3rd November 2019, me and my team joined the SVATTT (Asean Student Contest on Information Security) qualification round. We joined in under the name "noobiens" and luckily ranked second in the South region. This is our writeup to the reversing challenge "0day hunter". This challenge is from @anhdaden, who recently claimed a VMWare bug to escape virtual box. Without furthur ado, let's get started.

# The challenge
The challenge gives us two folders, *challenge* and *tool*. In side *tool*, there is an AFL binary. AFL is a fuzzing tool created by Google, you can find the source for the tool on [Github](https://github.com/google/AFL). However, this challenge uses a modified version of the fuzzer. We took quite a time looking on AFL for the solution but it was not the right approach. The challenge folder has a binary named `fileinfo.exe`, `fuzz.bat`, a folder *seeds* and a `winafl.dll` dynamic library file.

We are told to find the flag in `fileinfo.exe` and so we did, the file is not very big, it will read the input file and output information of the file.
```python
if __name__ == "__main__":
  import sys
  if len(sys.argv) != 2:
    exit()
  filename = sys.argv[1]
  filebuf = open(filename, 'rb').read()
  printFilename(filebuf)
  printHex(filebuf)
  printBase64(filebuf)
  printCRC32(filebuf)
  printFileType(filebuf)
```

The first 4 functions is very small and understandable, but the **FileType** function is very big. However, looking a few of the instruction, it basically checks the first few bytes for signature. If we went to the strings section, we can see strings like:
```
.rdata:0000000000405050	00000020	C	Palm Desktop To Do Archive file
.rdata:0000000000405070	00000023	C	Palm Desktop Calendar Archive file
.rdata:0000000000405093	0000001B	C	Computer icon encoded file
.rdata:00000000004050AE	00000019	C	MPEG Program Stream file
.rdata:00000000004050C7	00000018	C	WebAssembly binary file
.rdata:00000000004050E0	0000001F	C	PCAP Next Generation Dump file
.rdata:00000000004050FF	00000014	C	PostScript document
.rdata:0000000000405113	0000000D	C	PDF document
```

And if we look further, we see this magic string
```
.rdata:00000000004052BE	0000000C	C	SVATTT file
```

And this points us toward
```
.text:000000000040204E                 cmp     eax, 'S'
.text:0000000000402051                 jz      loc_40258B
.text:0000000000402057                 jmp     loc_40273A

.text:000000000040258B loc_40258B:                             ; CODE XREF: sub_401FC7+8A↑j
.text:000000000040258B                 mov     rax, [rbp+filebuf]
.text:000000000040258F                 add     rax, 1
.text:0000000000402593                 movzx   eax, byte ptr [rax]
.text:0000000000402596                 cmp     al, 'V'
.text:0000000000402598                 jnz     short loc_4025EB
.text:000000000040259A                 mov     rax, [rbp+filebuf]
.text:000000000040259E                 add     rax, 2
.text:00000000004025A2                 movzx   eax, byte ptr [rax]
.text:00000000004025A5                 cmp     al, 'A'
.text:00000000004025A7                 jnz     short loc_4025EB
.text:00000000004025A9                 mov     rax, [rbp+filebuf]
.text:00000000004025AD                 add     rax, 3
.text:00000000004025B1                 movzx   eax, byte ptr [rax]
.text:00000000004025B4                 cmp     al, 'T'
.text:00000000004025B6                 jnz     short loc_4025EB
.text:00000000004025B8                 mov     rax, [rbp+filebuf]
.text:00000000004025BC                 add     rax, 4
.text:00000000004025C0                 movzx   eax, byte ptr [rax]
.text:00000000004025C3                 cmp     al, 'T'
.text:00000000004025C5                 jnz     short loc_4025EB
.text:00000000004025C7                 mov     rax, [rbp+filebuf]
.text:00000000004025CB                 add     rax, 5
.text:00000000004025CF                 movzx   eax, byte ptr [rax]
.text:00000000004025D2                 cmp     al, 'T'
.text:00000000004025D4                 jnz     short loc_4025EB
.text:00000000004025D6                 lea     rcx, aSvatttFile ; "SVATTT file"
.text:00000000004025DD                 call    puts
.text:00000000004025E2                 mov     rcx, [rbp+filebuf]
.text:00000000004025E6                 call    svattt_print
```

It checks the first 6 bytes for SVATTT, and call a function.
```
.text:0000000000401A11 sbox            = byte ptr -120h
.text:0000000000401A11 key             = byte ptr -20h
.text:0000000000401A11 output          = qword ptr -10h
.text:0000000000401A11 counter         = dword ptr -4
.text:0000000000401A11 filebuf         = qword ptr  10h
.text:0000000000401A11
.text:0000000000401A11                 push    rbp
.text:0000000000401A12                 sub     rsp, 140h
.text:0000000000401A19                 lea     rbp, [rsp+80h]
.text:0000000000401A21                 mov     [rbp+0C0h+filebuf], rcx
.text:0000000000401A28                 mov     [rbp+0C0h+output], 0
.text:0000000000401A33                 mov     dword ptr [rbp+0C0h+key], 0
.text:0000000000401A3D                 mov     word ptr [rbp+0C0h+key+4], 0
.text:0000000000401A46                 mov     [rbp+0C0h+key+6], 0
.text:0000000000401A4D                 mov     [rbp+0C0h+key], 9Fh
.text:0000000000401A54                 mov     [rbp+0C0h+key+4], 98h
.text:0000000000401A5B                 mov     [rbp+0C0h+key+1], 9Ah
.text:0000000000401A62                 mov     [rbp+0C0h+key+3], 98h
.text:0000000000401A69                 mov     [rbp+0C0h+key+2], 8Dh
.text:0000000000401A70                 mov     [rbp+0C0h+key+5], 98h
.text:0000000000401A77                 mov     [rbp+0C0h+counter], 0
.text:0000000000401A81                 jmp     short loc_401AAE
.text:0000000000401A83 ; ---------------------------------------------------------------------------
.text:0000000000401A83
.text:0000000000401A83 loc_401A83:                             ; CODE XREF: svattt_print+A4↓j
.text:0000000000401A83                 mov     eax, [rbp+0C0h+counter]
.text:0000000000401A89                 cdqe
.text:0000000000401A8B                 movzx   eax, [rbp+rax+0C0h+key]
.text:0000000000401A93                 xor     eax, 0FFFFFFCCh
.text:0000000000401A96                 mov     edx, eax
.text:0000000000401A98                 mov     eax, [rbp+0C0h+counter]
.text:0000000000401A9E                 cdqe
.text:0000000000401AA0                 mov     [rbp+rax+0C0h+key], dl
.text:0000000000401AA7                 add     [rbp+0C0h+counter], 1
.text:0000000000401AAE
.text:0000000000401AAE loc_401AAE:                             ; CODE XREF: svattt_print+70↑j
.text:0000000000401AAE                 cmp     [rbp+0C0h+counter], 5
.text:0000000000401AB5                 jle     short loc_401A83
.text:0000000000401AB7                 mov     rcx, [rbp+0C0h+filebuf]
.text:0000000000401ABE                 call    strlen
.text:0000000000401AC3                 add     rax, 1
.text:0000000000401AC7                 mov     rcx, rax
.text:0000000000401ACA                 call    malloc
.text:0000000000401ACF                 mov     [rbp+0C0h+output], rax
.text:0000000000401AD6                 cmp     [rbp+0C0h+output], 0
.text:0000000000401ADE                 jz      short loc_401B5E
.text:0000000000401AE0                 lea     rdx, [rbp+0C0h+sbox]
.text:0000000000401AE4                 lea     rax, [rbp+0C0h+key]
.text:0000000000401AEB                 mov     rcx, rax
.text:0000000000401AEE                 call    sub_4015D8
.text:0000000000401AF3                 mov     rdx, [rbp+0C0h+output]
.text:0000000000401AFA                 lea     rax, [rbp+0C0h+sbox]
.text:0000000000401AFE                 mov     r8, rdx
.text:0000000000401B01                 mov     rdx, [rbp+0C0h+filebuf]
.text:0000000000401B08                 mov     rcx, rax
.text:0000000000401B0B                 call    sub_401977
.text:0000000000401B10                 mov     rax, [rbp+0C0h+output]
.text:0000000000401B17                 mov     r8d, 34h
.text:0000000000401B1D                 lea     rdx, blob       ; Size
.text:0000000000401B24                 mov     rcx, rax
.text:0000000000401B27                 call    memcmp
.text:0000000000401B2C                 test    eax, eax
.text:0000000000401B2E                 jnz     short loc_401B5E
.text:0000000000401B30                 mov     rdx, [rbp+0C0h+filebuf]
.text:0000000000401B37                 lea     rcx, aMessageS  ; "Message: %s\n"
.text:0000000000401B3E                 call    printf
.text:0000000000401B43                 mov     edx, '{'
.text:0000000000401B48                 mov     rcx, [rbp+0C0h+filebuf]
.text:0000000000401B4F                 call    strchr
.text:0000000000401B54                 test    rax, rax
.text:0000000000401B57                 jz      short loc_401B5E
.text:0000000000401B59                 call    abort
.text:0000000000401B5E ; ---------------------------------------------------------------------------
.text:0000000000401B5E
.text:0000000000401B5E loc_401B5E:                             ; CODE XREF: svattt_print+CD↑j
.text:0000000000401B5E                                         ; svattt_print+11D↑j ...
.text:0000000000401B5E                 nop
.text:0000000000401B5F                 add     rsp, 140h
.text:0000000000401B66                 pop     rbp
.text:0000000000401B67                 retn
```

What the function does is
```python
def svatttfile(filebuf):
  key = [0x9f, 0x9a, 0x8d, 0x98, 0x98, 0x98]
  for i in range(len(key)):
    key[i] ^= 0xcc
  # guess what it will output? [S, V, A, T, T, T]

  arr1 = [0 for i in range(0x60)]    # rbp-0x60
  arr2 = [0 for i in range(size(filebuf))]

  secret_func1(key, arr1)
  secret_func2(arr1, filebuf, arr2)

  if (memcmp(arr2, SOMEARR, 34) == 0):
    print("Message %s" % filebuf)
    if ('{' in filebuf):
      abort()
```

At this point, our team thought that we need to fuzz to get input of the **secret_func1** and **secret_func2**. We spent a lot of time looking for ways to generate fuzzing input file without knowing that it is the wrong direction. The README distracted us from going the right way and try to reverse **secret_funcs**. Until the hint comes:

> It's RC4

It all clear now, they "really" want us to reverse the functions, not fuzzing it. So we get back to the file, throwing all the RC4 implementation online we could find to solve this challenge. We have the result buffer SOMEARR, and the key, we just need to decrypt using RC4. But it didn't work, **secret_func1** looks just like KSA step in RC4, but PRGA is nowhere alike. Out teamate @pickaxe find the difference, and rewrite the script. And we get message.
```python
def crypt():
	plain = "DACB317F819820386CCF03A7FF04645E46FD5FE7037EB1DABBE1EB0E67703BCCF29E049381284107F1F9079ACF36DE42970C25A7".decode('hex')
	S = [0xD7,0x0E,0xF6,0x9E,0xC4,0x9C,0x7C,0xB2,0x8D,0x44,0x3B,0x1A,0x20,0xD6,0x17,0xCE,0x74,0x52,0xFF,0x35,0xB5,0x58,0xB8,0xF7,0xF8,0x4C,0x95,0xE6,0xAC,0x70,0xE7,0x86,0x43,0x62,0xE8,0x42,0xC3,0x89,0x59,0xE9,0x93,0xE4,0xEC,0xE2,0xEA,0xF9,0x2F,0x47,0xE0,0x05,0x73,0xED,0x4A,0xEB,0xA4,0x5A,0xCD,0xB1,0x46,0x80,0x02,0xEE,0xA9,0x3A,0x15,0xB4,0xB7,0xFA,0x03,0xC2,0x04,0xDF,0xEF,0xBE,0xDE,0x6F,0x5B,0xD3,0x9B,0x79,0x83,0xDD,0x25,0xF0,0xAB,0xA6,0x92,0x65,0xDC,0x38,0xFB,0x32,0xD2,0xF2,0x87,0x0F,0xDB,0x91,0xF1,0x2A,0x5D,0x21,0xCB,0x96,0x99,0xDA,0x10,0x76,0xF3,0x1D,0x7B,0xD1,0x18,0xFC,0xB3,0x28,0x81,0x1E,0x55,0xA8,0x51,0x01,0xC1,0x36,0xF4,0x26,0x71,0xCA,0x24,0xC5,0xD0,0x56,0x63,0x90,0xD9,0xB9,0x7D,0xA3,0x69,0x8C,0xFD,0xF5,0x6A,0xD8,0x1B,0x0D,0x45,0xFE,0x72,0x66,0xCF,0x77,0x09,0xC9,0x7E,0xC0,0x6C,0x78,0x0C,0x4F,0x2C,0x1C,0x7F,0x00,0x8E,0x29,0x97,0x13,0x9A,0x39,0x14,0x3D,0x07,0x54,0x88,0x98,0x57,0x16,0x0A,0x27,0x5F,0x84,0xA1,0x11,0xA0,0x41,0x9D,0x37,0x85,0xB6,0x4B,0x6E,0x2E,0x4E,0x68,0xBF,0x64,0xAD,0x12,0x34,0xA7,0x0B,0x3F,0x8A,0x5C,0x67,0x8B,0xBC,0x40,0xBD,0xBA,0xCC,0x33,0x06,0x50,0x31,0x82,0x61,0x94,0x30,0x60,0x08,0xAE,0xC7,0x3E,0x1F,0x8F,0xD4,0x19,0xA2,0xD5,0x48,0x3C,0x23,0xE5,0xBB,0xE3,0x5E,0x75,0x49,0x6D,0xC6,0x6B,0xB0,0x7A,0xAA,0x4D,0xAF,0xC8,0xE1,0x22,0x9F,0x53,0x2D,0xA5,0x2B]

	cipherList = []
	i = 0
	j = 0

	for m in range(len(plain)):
		i = (i + 1) % 256
		j = (j + S[i]) % 256
		S[i], S[j] = S[j], S[i]
		k = S[(S[i] + S[j]) % 256]
		cipherList.append(k ^ ord(plain[m]))

	return cipherList

print(''.join(map(chr, crypt())))
```

plain is SOMEARR, and S is the arr1 we get after **secret_func1**.

> SVATTT hint: you may wanna take a look at winafl.dll

Ok, I'm fine! And we went on looking at *winafl.dll*. There are many functions, I cannot find any function that looks like a flag function. Turns out, there is a function that will modify the check buffer while the fuzzer is running. Again, my teammate @pickaxe found it, he notice a function that changes the `memcmp` to another function. Oh my f***ing wow.
```
mov     rcx, [rbx]
lea     rdx, aMemcmp    ; "memcmp"
call    dr_get_proc_address
lea     rdx, foo
xor     r8d, r8d
mov     rcx, rax
call    drwrap_wrap
```

(I saw this function once but a whole lot numbers didn't get me anything so I skipped it, didn't know I was looking at the right place)

And again, it's RC4, the buffer being compared to SOMEARR is changed to
```
mov     dword ptr [rbp+var_40], 7F31CBDAh
mov     dword ptr [rbp+var_40+4], 387B9881h
mov     dword ptr [rbp+var_38], 0A707D571h
mov     dword ptr [rbp+var_38+4], 526F52F0h
mov     dword ptr [rbp+var_30], 0F153F108h
mov     dword ptr [rbp+var_30+4], 9ABF6051h
mov     [rbp+var_28], 55ACF2BAh
mov     [rbp+var_24], 9F3D7462h
mov     [rbp+var_20], 931AD9BCh
mov     [rbp+var_1C], 393E339Bh
mov     [rbp+var_18], 8107ABE1h
mov     [rbp+var_14], 469627C0h
mov     [rbp+var_10], 0B62505CDh
```

Quickly I re-wrote the script to decrypt this
```python
from pwn import *
plain = ''.join([
  p32(0x7F31CBDA),
  p32(0x387B9881),
  p32(0x0A707D571),
  p32(0x526F52F0),
  p32(0x0F153F108),
  p32(0x9ABF6051),
  p32(0x55ACF2BA),
  p32(0x9F3D7462),
  p32(0x931AD9BC),
  p32(0x393E339B),
  p32(0x8107ABE1),
  p32(0x469627C0),
  p32(0x0B62505CD)
])
```

Rerun the file, we got:

> SVATTT{http://dynamorio.org/docs/group__drwrap.html}

5h42m just 3 minutes till the end of the contest. Rising from rank 11 to rank 4 country. It was a big relief, I thought we couldn't make it. Thank you @pickaxe for being very patient till the end of the contest. That last minute was huge achievement.
