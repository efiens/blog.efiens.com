---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "[EFIENS Internal CTF] Crypto Writeups"
subtitle: ""
summary: ""
authors: [npn]
tags: []
categories: []
date: 2020-10-27T21:24:46+07:00
lastmod: 2020-10-27T21:24:46+07:00
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

## Warm up
We are given 2 files:

`chall.py`
```python
#!/usr/bin/env python3
 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from secret import flag
 
 
class ByteHolder():
    def __init__(self, b=0):
        assert 0 <= b <= 255
        self.byte = b
 
    def set_byte(self, b):
        assert 0 <= b <= 255
        self.byte = b
 
 
class KeyHolder():
    def __init__(self):
        self.bytes = [ByteHolder()] * 16
 
    def set_key(self, key):
        assert len(key) == 16
        for i in range(16):
            self.bytes[i].set_byte(key[i])
 
    def get_key(self):
        return b''.join(bytes([x.byte]) for x in self.bytes)
 
 
def encrypt(m, keys):
    c = m
    if len(c) % 16 != 0:
        c = pad(c, 16)
    for key in keys:
        aes = AES.new(key, AES.MODE_CBC, b'IVIVIVIVIVIVIVIV')
        c = aes.encrypt(c)
    return c
 
 
if __name__ == '__main__':
    obj = KeyHolder()
    keys = []
    for _ in range(4):
        obj.set_key(os.urandom(16))
        keys.append(obj.get_key())
 
    m = b'C4N_U_BR34K_MY_4ES?'
    c = encrypt(m, keys)
    flagenc = encrypt(flag, keys)
 
    print((c.hex(), flagenc.hex()))
```

and `output.txt`
```
('fdaa7d3d2ca7426c6dcdcc030a9c7fc602828bd79865c50f145cec7be7a00925', 'f511ef2c87336810c749a826248ac76e7cbe8a4bd08602f50323f0b53ef7e5bf48de2e07f91752a1c3072b56108a14d1')
```

Long story short, the encryption scheme used here is 4 rounds of AES-CBC with a given IV and 4 randomly-generated constant keys, namely k0, k1, k2, k3. Our objective is to recover the 4 keys from a given (plaintext, ciphertext) pair, in order to recover the flag from its ciphertext. Just a reminder: each key is 16-byte long! However, the task is not as burdensome as what it seems to be since the definition of the __init__ method of KeyHolder is self.bytes = [ByteHolder()] * 16, which is a [shallow copy](https://realpython.com/copying-python-objects/), which in turn leads to the fact that every time an element of bytes changes, the whole list would change to it. That means after each round of generating a random 16-byte key, the result is just a random byte being duplicated 16 times.

'So what now?' You may ask.

Well, from now on we just need to brute-force over 256^4 = 4294967296 (k0, k1, k2, k3) quadruples. But that is still so much work to do, so [Meet-in-the-middle](https://en.wikipedia.org/wiki/Meet-in-the-middle_attack) attack is a more comfortable and reasonable approach.
Using the given (plaintext, final ciphertext) pair, we just need to brute-force over every possible (k0, k1) combinations to find possible ciphertext's after 2 encryption rounds from plaintext (65536 cases) (1). Next, brute-force over every possible (k2, k3) combinations to find possible ciphertext's after 2 decryption rounds from final ciphertext (65536 cases) (2).
ciphertext produced by (1) and (2) must be the same since there exists a quadruple (k0, k1, k2, k3) to connect plaintext and final ciphertext.
Finally, the desired ciphertext (found using set.intersection()) will reveals the 4 keys, which can then be used to decrypt the flag's ciphertext to get flag.

Here is my solution:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
 
def xor(b1, b2):
    return bytes([x^y for x,y in zip(b1,b2)])
 
def encrypt(m, keys):
    c = m
    for key in keys:
        aes = AES.new(key, AES.MODE_ECB, b'IVIVIVIVIVIVIVIV')
        c = aes.encrypt(c)
    return c
 
c = binascii.unhexlify('fdaa7d3d2ca7426c6dcdcc030a9c7fc602828bd79865c50f145cec7be7a00925')[:16]
m = pad(b'C4N_U_BR34K_MY_4ES?', 16)[:16]
IV = b'IVIVIVIVIVIVIVIV'
 
flag = binascii.unhexlify('f511ef2c87336810c749a826248ac76e7cbe8a4bd08602f50323f0b53ef7e5bf48de2e07f91752a1c3072b56108a14d1')
 
#MITM
c_mid1 = []
for i in range(65536):
    k0 = bytes([i % 256])*16
    k1 = bytes([i // 256])*16
    aes0 = AES.new(k0, AES.MODE_ECB)
    aes1 = AES.new(k1, AES.MODE_ECB)
    c0 = aes0.encrypt(xor(m, IV))
    c_mid1 += [aes1.encrypt(xor(c0, IV))]
 
c_mid2 = []
for j in range(65536):
    k2 = bytes([j % 256])*16
    k3 = bytes([j // 256])*16
    aes2 = AES.new(k2, AES.MODE_ECB)
    aes3 = AES.new(k3, AES.MODE_ECB)
    c2 = xor(aes3.decrypt(c), IV)
    c_mid2 += [xor(aes2.decrypt(c2), IV)]
 
same = list(set(c_mid1).intersection(c_mid2))
assert len(same) == 1 #make sure that there is only 1 meeting point
same = same[0]
 
i = c_mid1.index(same)
k0 = bytes([i % 256])*16
k1 = bytes([i // 256])*16
j = c_mid2.index(same)
k2 = bytes([j % 256])*16
k3 = bytes([j // 256])*16
 
keys = [k3, k2, k1, k0]
for key in keys:
    aes = AES.new(key, AES.MODE_CBC, IV)
    flag = aes.decrypt(flag)
 
flag = unpad(flag, 16)
print(flag)
```

Flag is `EFIENS{Us3_L1sT_C0mPr3H3nS10N!-.-}`

## Baby RSA
We are given 2 files:

`chall.py`
```python
#!/usr/bin/env python3
 
from Crypto.Util.number import *
from secret import flag
 
if __name__ == '__main__':
    p = getPrime(1024)
    q = getPrime(1024)
    n = p*q
    l = (p & q) * (p ^ q) | 0x1337
    c = pow(bytes_to_long(flag), 65537, n)
 
    print(f'n = {hex(n)}\n')
    print(f'l = {hex(l)}\n')
    print(f'c = {hex(c)}\n')
```

and `output.txt`
```
n = 0x723311aadeef6dd62b68ec253763c1ea38807fd29c4fc07e28f072aa545c46aeacdb647556beb463bebc9e4bdb16a03109ec3895faa222e5931c4de51773f176c109167f819b6a908ada431ad61804ffff16c21f79e6c89e73f7bdfd45f4f179630d773a6963b2123665dd4ced88cd88317ad82ac7f7ad7a1d79c0ca0b7d6aa9b87765fd6b2dbd2dcff2691d7f3ac005f8b1eecc453237aa4a0039bf984e7f293c5af058885eeffb9175c50eeef57e9139065ac11af54547f2574190190340d1d5bd2c45b5c3eca7a35095f0b79862f29621e95fd15f367eb09661bf7fa9f11d424a2732bca7783675d172348f9bb2d7603360b6cd14f443e3c55bd9a4fd9ead
 
l = 0x2c949e595e80defd3fbb97fbacd909a119ec4d01908bc5886c2473d20a2d1b1ddf906412ec69ceb18f92a4d7ec2a2e211e0cc9152b57cb51a6edfabd0278d8600b6ee3bf891c5551600f57ccc076690cad6354875811302c16fe3d007fa213314cca14fc3faebef931fc5af1367f0960400136890c89ef65654783418473efb7f0c9d908fbc0b2e7e1c6db3338b0f9f3934c2e79637254c135d75ce8d817589ab824d636dac94401c60b95bcb3e20c9dcde766600b421c30a98a35cfff20d499284015258a94deca75812982f072c8dec714658f7ea5d448d39bd8acb1faa74e1d123c968a489a33d1ef457df8666a953ec8e3f201c5da4d5cc1bc20da58fb3f
 
c = 0x4b49ee5cc75d85944642fb7c3b105c6d657001b0a25ed80a91f75c2a6173d332ac298eb9a6b1bc055f9a189aea41fb701038bcb4287d7c29aa2826da73f198975617d2d5b8f63e51a29b4bdbaab9b8dd945988af4b63f6c72d51b12c481db7aa57513284ab3c1def98eaa23f1462054a6aa551a407a5f2508cce1ef77df1b20d2bc7be87ec1616895d54d68c7c72d2ca9d582bacbd5a2c118ff426528f53dcba6bbb74a7271d6cc87d6d14d0ea06d195b583566ef2f0350196725d8a13ff3e44623a3b0f545b764e25f234552e5707e8a806ea067ce8d7cc273e63d3de2a499f10a855d6ddf13aa3d51119c45948609711a6dc011642f481155bcde5d4c0fbfa
```

Good old RSA challenges, the point is (all-the-time) if we can factor n = p * q, we will have phi, given e, we will have d, given c, we will have m, and we will use long_to_bytes to retrieve the flag.
Unfortunately, n is too big so factordb cannot handle it. On the other hand, we are given l, which is calculated by p and q using some bitwise operation, so how can we get any hint about p and q base on l? The answer is to think 'bitwisely', and the use of bitwise operation might actually a hint.
Note that the last k bits of n and l solely base on the last k bits of p and q. To put it more clearly, the fact that the last 3 bits of n is 001 totally relies on the fact that the last 3 bits of p is e.g. 011 and the last 3 bits of q is e.g. 101, not concerning what the 4th, 5th, 6th bit is.
With this in mind, one can brute-force p and q bit-by-bit by using n and l to shortlist the candidates.

Here is my solution:
```python
from Crypto.Util.number import long_to_bytes
 
#the function to compute l from p and q
def comp(p, q):
    return (p & q) * (p ^ q) | 0x1337
 
#res is l, I mean the desired_result for the construction phase
res = 0x2c949e595e80defd3fbb97fbacd909a119ec4d01908bc5886c2473d20a2d1b1ddf906412ec69ceb18f92a4d7ec2a2e211e0cc9152b57cb51a6edfabd0278d8600b6ee3bf891c5551600f57ccc076690cad6354875811302c16fe3d007fa213314cca14fc3faebef931fc5af1367f0960400136890c89ef65654783418473efb7f0c9d908fbc0b2e7e1c6db3338b0f9f3934c2e79637254c135d75ce8d817589ab824d636dac94401c60b95bcb3e20c9dcde766600b421c30a98a35cfff20d499284015258a94deca75812982f072c8dec714658f7ea5d448d39bd8acb1faa74e1d123c968a489a33d1ef457df8666a953ec8e3f201c5da4d5cc1bc20da58fb3f
n = 0x723311aadeef6dd62b68ec253763c1ea38807fd29c4fc07e28f072aa545c46aeacdb647556beb463bebc9e4bdb16a03109ec3895faa222e5931c4de51773f176c109167f819b6a908ada431ad61804ffff16c21f79e6c89e73f7bdfd45f4f179630d773a6963b2123665dd4ced88cd88317ad82ac7f7ad7a1d79c0ca0b7d6aa9b87765fd6b2dbd2dcff2691d7f3ac005f8b1eecc453237aa4a0039bf984e7f293c5af058885eeffb9175c50eeef57e9139065ac11af54547f2574190190340d1d5bd2c45b5c3eca7a35095f0b79862f29621e95fd15f367eb09661bf7fa9f11d424a2732bca7783675d172348f9bb2d7603360b6cd14f443e3c55bd9a4fd9ead
c = 0x4b49ee5cc75d85944642fb7c3b105c6d657001b0a25ed80a91f75c2a6173d332ac298eb9a6b1bc055f9a189aea41fb701038bcb4287d7c29aa2826da73f198975617d2d5b8f63e51a29b4bdbaab9b8dd945988af4b63f6c72d51b12c481db7aa57513284ab3c1def98eaa23f1462054a6aa551a407a5f2508cce1ef77df1b20d2bc7be87ec1616895d54d68c7c72d2ca9d582bacbd5a2c118ff426528f53dcba6bbb74a7271d6cc87d6d14d0ea06d195b583566ef2f0350196725d8a13ff3e44623a3b0f545b764e25f234552e5707e8a806ea067ce8d7cc273e63d3de2a499f10a855d6ddf13aa3d51119c45948609711a6dc011642f481155bcde5d4c0fbfa
possible = []
for bp in range(2):
    for bq in range(2):
        if bin(comp(bp, bq))[-1] == bin(res)[-1] and bin(bp*bq)[-1] == bin(n)[-1]:
            possible += [(bp, bq)]
 
#construction of p and q phase base on the l's computation
check = []
dig = 1
while len(check) == 0:
    key = 1 << dig
    dig += 1
    if dig % 100 == 0:
        print(dig) #to keep track of the progress
    poss = []
    for p, q in possible:
        for bp in range(2):
            for bq in range(2):
                #the last 'dig' bits of p and q when decided must result in the last 'dig' bits of the predetermined n and l after the calculations
                if bin(comp(p + bp*key, q + bq*key))[2:].zfill(dig+1)[-dig:] == bin(res)[2:].zfill(dig+1)[-dig:] and bin((p + bp*key)*(q + bq*key))[2:].zfill(dig+1)[-dig:] == bin(n)[2:].zfill(dig+1)[-dig:]:
                    poss += [(p + bp*key, q + bq*key)]
    possible = poss
    check = [(a, b) for a, b in possible if comp(a, b) == res]
 
#filtering phase
for p, q in check:
    if p*q == n:
        break
 
#RSA trivia
phi = (p-1) * (q-1)
e = 65537
d = pow(e, -1, phi)
m = long_to_bytes(pow(c, d, n))
 
print(m)
```

Flag is `EFIENS{Y0U_D0_KN0W_H0W_T0_F4CT0R!!!!!!!!!!!!!}`

## Baby ECC

We are given 2 files:

`chall.py`
```python
#!/usr/bin/env python3
 
from fastecdsa.curve import Curve
from fastecdsa.point import Point
from Crypto.Util.number import *
from secret import p, a, b, q, gx, gy, px, py, flag
 
BabyEC = Curve('BabyEC', p, a, b, q, gx, gy)
 
P = Point(px, py, curve=BabyEC)
Q = bytes_to_long(flag) * P
R = 1337 * P
 
print(f'G = ({hex(gx)}, {hex(gy)})\n')
print(f'P = ({hex(P.x)}, {hex(P.y)})\n')
print(f'Q = ({hex(Q.x)}, {hex(Q.y)})\n')
print(f'R = ({hex(R.x)}, {hex(R.y)})\n')
```

and `output.txt`:
```
G = (0x47f85baefdfa332769d34221a0c07431219f8c493683b009ba2aa3da1b8bf0, 0x46610590278b17cf380627db67fc528eee26cc287181e11f7759cb8f7940ea)
 
P = (0x340f7272f03ca73076bc9990981a0a367609f24b449463b85ae8b2fe049d2c, 0x423c07063858f467c5c6e2c23369c3f2eb4e9c6755f02dd6b000816d58969)
 
Q = (0x39b924f2e5ab270c7edcd0e2587da5e470f582375c5d978d73f39c27c9a771, 0x46e654d2c9c0215a0df753204df13536bebb2aee53285abd766878e85a91ad)
 
R = (0x612ba8fcfb8c054ff2dd5e52872450c99736b110b9e9771dc2d34bb18330a6, 0x4646b87d1033fe0bc12a126186de57a8e6fe4fee216476011856496b0acb05)
```

along with the hint: **Are you Smart enough?**

At first sight, this is an ECC challenge without the curve parameters p, a, and b so we have to find out ourselves. Checking for the coordinates' bit_length of 4 given points, I conjectured that p is a 247-bit number.

```python
>>> list(map(lambda pt : (pt[0].bit_length(), pt[1].bit_length()), [G, P, Q, R]))
[(247, 247), (246, 243), (246, 247), (247, 247)]
```

Furthermore, p is prime since this is a standard ECC problem without special notes. Now, our first goal is to rearrange some equations to deduce p, a, and b from the 4 points, namely $(x_1, y_1), (x_2, y_2), (x_3, y_3)$ and $(x_4, y_4)$. Since they are on the curve $y^2 = x^3 + ax + b \pmod p$, we have:

$$y_1^2 \equiv x_1^3 + ax_1 + b \pmod p$$
$$y_2^2 \equiv x_2^3 + ax_2 + b \pmod p$$
$$y_3^2 \equiv x_3^3 + ax_3 + b \pmod p$$
$$y_4^2 \equiv x_4^3 + ax_4 + b \pmod p$$

Rearranging gives:

$$ax_1 + b \equiv y_1^2 - x_1^3 \equiv X_1 \pmod p\ (1)$$
$$ax_2 + b \equiv y_2^2 - x_2^3 \equiv X_2 \pmod p$$
$$ax_3 + b \equiv y_3^2 - x_3^3 \equiv X_3 \pmod p$$
$$ax_4 + b \equiv y_4^2 - x_4^3 \equiv X_4 \pmod p$$

Isolating b in each equation gives:

$$b \equiv X_1 - ax_1 \equiv X_2 - ax_2 \equiv X_3 - ax_3 \equiv X_4 - ax_4 \pmod p$$

Rearranging gives:

$$a(x_1 - x_2) \equiv X_1 - X_2 \pmod p\ (2)$$
$$a(x_3 - x_4) \equiv X_3 - X_4 \pmod p$$

Multiply both sides of the two equations down, we have:

$$a(x_1 - x_2)(X_3 - X_4) \equiv a(x_3 - x_4)(X_1 - X_2) \pmod p$$

Since p is prime, $gcd(a, p) = 1$, so we can cancel out a from both side of the equation:

$$(x_1 - x_2)(X_3 - X_4) - (x_3 - x_4)(X_1 - X_2) \equiv 0 \pmod p$$

In other words, $p\ |\ S$ with $S = (x_1 - x_2)(X_3 - X_4) - (x_3 - x_4)(X_1 - X_2)$, so p must be a factor of S. But
```
from factordb.factordb import FactorDB
G = (0x47f85baefdfa332769d34221a0c07431219f8c493683b009ba2aa3da1b8bf0, 0x46610590278b17cf380627db67fc528eee26cc287181e11f7759cb8f7940ea)
P = (0x340f7272f03ca73076bc9990981a0a367609f24b449463b85ae8b2fe049d2c, 0x423c07063858f467c5c6e2c23369c3f2eb4e9c6755f02dd6b000816d58969)
Q = (0x39b924f2e5ab270c7edcd0e2587da5e470f582375c5d978d73f39c27c9a771, 0x46e654d2c9c0215a0df753204df13536bebb2aee53285abd766878e85a91ad)
R = (0x612ba8fcfb8c054ff2dd5e52872450c99736b110b9e9771dc2d34bb18330a6, 0x4646b87d1033fe0bc12a126186de57a8e6fe4fee216476011856496b0acb05)
 
x = list(map(lambda pt : pt[0], [G, P, Q, R]))
y = list(map(lambda pt : pt[1], [G, P, Q, R]))
X = list(map(lambda x_, y_ : y_**2 - x_**3, x, y))
 
S = (x[0] - x[1])*(X[2] - X[3]) - (x[2] - x[3])*(X[0] - X[1])
f = FactorDB(S)
f.connect()
print(f.get_factor_list())
```

gives us

```
[3, 3, 3, 3, 5, 7, 7, 180990996245833, 14376023133604078596737150896626004046596809977857578638131522973620386384210375086709308252753447923674490280014359938401044608635497563756998961923811965522726393490209315153832045048515532195734890589198725132296614931476302745568155857618122553749122098327664526837502985687]
```

So S is still too large to be feasibly factored using our tool (factordb and alpertron), and we must come up with a workaround.
That is, to notice $gcd(X_3 - X_4, X_1 - X_2)$ is a not-to-big number and from the equation of S, that not-to-big number must be a factor of S. Then we can factor it in the hope that p would be found.

```python
>>> np.gcd(X[2] - X[3], X[0] - X[1])
6557354037413203030257288478090739482749862682296070906932046789161747395665
>>> f = FactorDB(_)
>>> f.connect()
<Response [200]>
>>> f.get_factor_list()
[5, 7, 187352972497520086578779670802592556649996076637030597340915622547478497019]
>>> _[-1].bit_length()
247
>>> f.get_status()
'FF'
```

And yes! A 247-bit prime number is found and it (really likely) is p.
Moreover, $(2) \Rightarrow a \equiv (X_1 - X_2)(x_1 - x_2)^{-1} \pmod p$ and $(1) \Rightarrow b \equiv X_1 - ax_1 \pmod p$.
So we have our curve parameters at hand:

```python
>>> p = f.get_factor_list()[-1]; p
187352972497520086578779670802592556649996076637030597340915622547478497019
>>> a = (X[0] - X[1]) * pow(x[0] - x[1], -1, p) % p; a
0
>>> b = (X[0] - a*x[0]) % p; b
94964716409202194999421760552335414529387279774715955962880178620755195968
```

The last phase is to solve for the discrete log problem to recover flag from P and Q, which is seemingly impossible. Fortunately, the challenge's hint said it all: the suspicious capitalized Smart did indeed imply Smart's attack against ECC, and an implementation of which can easily be found online.
Now we just need to put everything into SageMath to evaluate flag's value.
```
sage: p = 187352972497520086578779670802592556649996076637030597340915622547478497019
sage: a = 0
sage: b = 94964716409202194999421760552335414529387279774715955962880178620755195968
sage: E = EllipticCurve(GF(p), [a, b])
sage: P = E(0x340f7272f03ca73076bc9990981a0a367609f24b449463b85ae8b2fe049d2c, 0x423c07063858f467c5c6e2c23369c3f2eb4e9c6755f02dd6b000816d58969)
sage: Q = E(0x39b924f2e5ab270c7edcd0e2587da5e470f582375c5d978d73f39c27c9a771, 0x46e654d2c9c0215a0df753204df13536bebb2aee53285abd766878e85a91ad)
sage: SmartAttack(P, Q, p)
478115410503360055974110930823680446240935161179751428029481428727256189
```

Finally, `long_to_bytes` would reveal the flag.

Flag is `EFIENS{Y0U_R_S0_F***1Ng_SM4RT}`
