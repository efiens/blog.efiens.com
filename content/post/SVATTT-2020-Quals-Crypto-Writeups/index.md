---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "SVATTT 2020 Quals Crypto Writeups"
subtitle: ""
summary: ""
authors: [pcback]
tags: []
categories: []
date: 2020-11-04T10:32:04+07:00
lastmod: 2020-11-04T10:32:04+07:00
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

*Finally, some good cryptos :)*

- [Zozo](#zozo)
- [Impossible](#impossible)
- [Rijndael Ft. Arcfour](#rijndael-ft-arcfour)

## Zozo

```python
from Crypto.Util.number import getPrime
from secret import flag

if __name__ == "__main__":
    p = getPrime(2020)
    q = getPrime(2020)
    n = p * q
    m = int.from_bytes(flag, "big")
    print("m_nbits =", m.bit_length())
    print("n =", n)
    print("c =", pow(m, 2020, n))
    print("a =", pow(2020, p + q, n))
    print("b =", pow(2020 + p, q, n))

# Output:
# m_nbits = 319
# n = 6709908271017636273378655032643421210567975544297596915593470137128363891228419512657274114669011891942663090194905940777812561840118056588428615370768885092202739470181344818071226713472147749259310788573428481022337413249410993247950922905606644328528192943149444979234186887778743327152264963995552199639516334711772886596304023688804194352785222469981515261437190030385869298033630451369031363005751953854690763993170983549216454881262214787640404401540368982811803830518044862679244774316554303060596087036766585181264228754533884686157605874994816602077647771821154174017913840152663341574258319064731734285760120757142699366635818090921302212163494224026153096257118848542085578751569398418767290380960045993906298155744307585160054373394289318601600049110591936546458514375137447927136123305276472066985894412133850945593125430051050782975296823192677589524309974575965049652679106537699815859361332255355304073828912153633031918384020344454320846509291701047296552969792343877167445711589879582318737790689596530198981403204253053646510518423927646404039101183559872205057776835009335526749058360229304128875012756435061325738256749504976724101945923621936319816392889120956770374512063428722147098976329869
# c = 5864224848711720820817211671704694778695905148173426478823772341754769520297436790151720178822600703359634349693051017219994907057376876420682144309079454049023976356544836505728317828461198527983277715566118420702752363857780547934544333993684124272218912250542205291534959151403509560016811650493184981511608683386142308504929435507931615262448404799085994422034724586629678554166350178079472940420236074564061155766530450893276418007617083241365348685146022947027279870389893842842614241511586881271858702844985097949892504390163623182619199573989321882518783794640005487714616634923991074288211103528655178494133088391737888436621251297706643777790612880535035200633789617808463268702449003376758757849721087341450984385511290854783178315821367126481676592169755994541387156782192827145938301269351351761757778187189555776815049743584913347828959463932827039920965698827045664624051911631548912462614658429336371605254382418714300094185931900084689915127987428492388032885236529440573162080413658116170946312622966085259442254980477576414261877472891280475076723292584965680453174928254104610632650756393979776626931043914335355823274523183066437816628018798318931084472527823444775310790650495948742550122666265
# a = 980781179837305218885179206087048803444471590700302063643535018495693430724914030556245097393427260363913143528109538846693614829591697702120365428254385683345686839503177715773958743573268578603719463614159789566282009616211761285100706329150399807929446215401809997648819192178784790954736795499890038722047760536412541503802934220088682495579518726114052360115421374595601506367371502412838497878638171727147057117092423900868846945245783789452892823795098355454383460294933817930733670269626108689690340482888570822525974184471046978083084475955634871778999677709303300606494890899380058971976816822189144579808563376704948356613537488887920531445962766022108577853761563429626110136791087146101838675208582550451197200757032589215039999050104990561516363971216242857221975891670846525040094795082245693423133498139889346759731100028439885160329382113242431148999407896236749722176599862270989214245784974790773738512127225274712656701544006472542108326726757708387122994130188265336534967519742344235206902681790664982286969578284724535014551860462777351346235879265149601211212012635615413576036852957939185779471487479187069954869805725012786640528981369936114776694281309574922917292585167819126537098878393
# b = 4641216257378099057352381055721343077859730393779620957802677320836328299623919622682409180900043164006379743835208471861065322669689004219152209877688932161323939062172737862949209335612905959419049131122827606289833320132637091525870446228013750820759726221912426092978807761763953422452903897746886480698273729327700002205007278822192835444552715212503789831922772941247247255969897858427770953126012859725663442324952213635057881518395655943469500770643862064112328593634725795022717613503995768650624713368354255625278684619158673643673318377015067884394373976604294325761072623961601920844588611380160669668620997109083418668830300999523289352487100107863180219906337931959899035161077718190292946009520400669518771791347719094082165012180394779767868370586439398218340075663119372165826283115713174037872289972899332408490598997589851075336647868448921242054058992305185018532387107710133316926598562378231532319494830261025962503435937632030032541114261355373337463537885816018226679565761261843148303706086819008415654607508321193854761654672254054381663393374480552395442623530365395504895082051270910574308865251390812099708944795467910074283930491871014602632927379580666428504295668769812578759829434656
```

This is a RSA-like challenge, we know:

* $a \equiv 2020^{p+q} \pmod{n}$
* $b \equiv (2020+p)^{q} \pmod{n}$

Since $p \mid n$, we can take modulo $p$ from two equations above and get:

* $a \equiv 2020^{q+1} \pmod{p}$
* $b \equiv 2020^{q} \pmod{p}$

Therefore we can recover $p = GCD(a - 2020b, n)$.

Now $n$ is factored, but $GCD(2020, (p-1)(q-1)) = 4$ so we can't calculate inverse of $e$.

If $e = 4e_{1}$, $GCD(e_{1}, (p-1)(q-1)) = 1$ then we can get $d_{1} = e_{1}^{-1} \mod{(p-1)(q-1)}$ and $m^{4} = c^{d_{1}} \mod{n}$. Since $m$ is small (319 bits), $m^{4}$ is not reduced mod $n$, so we can recover $m$ by taking natural quad root.

```python
from sage.all import *

m_nbits = 319
n = 6709908271017636273378655032643421210567975544297596915593470137128363891228419512657274114669011891942663090194905940777812561840118056588428615370768885092202739470181344818071226713472147749259310788573428481022337413249410993247950922905606644328528192943149444979234186887778743327152264963995552199639516334711772886596304023688804194352785222469981515261437190030385869298033630451369031363005751953854690763993170983549216454881262214787640404401540368982811803830518044862679244774316554303060596087036766585181264228754533884686157605874994816602077647771821154174017913840152663341574258319064731734285760120757142699366635818090921302212163494224026153096257118848542085578751569398418767290380960045993906298155744307585160054373394289318601600049110591936546458514375137447927136123305276472066985894412133850945593125430051050782975296823192677589524309974575965049652679106537699815859361332255355304073828912153633031918384020344454320846509291701047296552969792343877167445711589879582318737790689596530198981403204253053646510518423927646404039101183559872205057776835009335526749058360229304128875012756435061325738256749504976724101945923621936319816392889120956770374512063428722147098976329869
c = 5864224848711720820817211671704694778695905148173426478823772341754769520297436790151720178822600703359634349693051017219994907057376876420682144309079454049023976356544836505728317828461198527983277715566118420702752363857780547934544333993684124272218912250542205291534959151403509560016811650493184981511608683386142308504929435507931615262448404799085994422034724586629678554166350178079472940420236074564061155766530450893276418007617083241365348685146022947027279870389893842842614241511586881271858702844985097949892504390163623182619199573989321882518783794640005487714616634923991074288211103528655178494133088391737888436621251297706643777790612880535035200633789617808463268702449003376758757849721087341450984385511290854783178315821367126481676592169755994541387156782192827145938301269351351761757778187189555776815049743584913347828959463932827039920965698827045664624051911631548912462614658429336371605254382418714300094185931900084689915127987428492388032885236529440573162080413658116170946312622966085259442254980477576414261877472891280475076723292584965680453174928254104610632650756393979776626931043914335355823274523183066437816628018798318931084472527823444775310790650495948742550122666265
a = 980781179837305218885179206087048803444471590700302063643535018495693430724914030556245097393427260363913143528109538846693614829591697702120365428254385683345686839503177715773958743573268578603719463614159789566282009616211761285100706329150399807929446215401809997648819192178784790954736795499890038722047760536412541503802934220088682495579518726114052360115421374595601506367371502412838497878638171727147057117092423900868846945245783789452892823795098355454383460294933817930733670269626108689690340482888570822525974184471046978083084475955634871778999677709303300606494890899380058971976816822189144579808563376704948356613537488887920531445962766022108577853761563429626110136791087146101838675208582550451197200757032589215039999050104990561516363971216242857221975891670846525040094795082245693423133498139889346759731100028439885160329382113242431148999407896236749722176599862270989214245784974790773738512127225274712656701544006472542108326726757708387122994130188265336534967519742344235206902681790664982286969578284724535014551860462777351346235879265149601211212012635615413576036852957939185779471487479187069954869805725012786640528981369936114776694281309574922917292585167819126537098878393
b = 4641216257378099057352381055721343077859730393779620957802677320836328299623919622682409180900043164006379743835208471861065322669689004219152209877688932161323939062172737862949209335612905959419049131122827606289833320132637091525870446228013750820759726221912426092978807761763953422452903897746886480698273729327700002205007278822192835444552715212503789831922772941247247255969897858427770953126012859725663442324952213635057881518395655943469500770643862064112328593634725795022717613503995768650624713368354255625278684619158673643673318377015067884394373976604294325761072623961601920844588611380160669668620997109083418668830300999523289352487100107863180219906337931959899035161077718190292946009520400669518771791347719094082165012180394779767868370586439398218340075663119372165826283115713174037872289972899332408490598997589851075336647868448921242054058992305185018532387107710133316926598562378231532319494830261025962503435937632030032541114261355373337463537885816018226679565761261843148303706086819008415654607508321193854761654672254054381663393374480552395442623530365395504895082051270910574308865251390812099708944795467910074283930491871014602632927379580666428504295668769812578759829434656

p = gcd(a - b*2020, n)
q = n // p

d1 = inverse_mod(2020//4, n-p-q+1)
m4 = pow(c, d1, n)

m = ZZ(m4).nth_root(4, truncate_mode=True)[0]
print(int(m).to_bytes(100, 'big').strip(b'\x00'))
```

The flag is: `ASCIS{pl4y1ng_w1th_p_4nd_q_1s_d4ng3r0us}`

## Impossible

```python
from bitarray import bitarray  # https://pypi.org/project/bitarray/
from bitarray.util import ba2int, int2ba


class PRNG:
    """Based on Linear Congruential Generator
    (https://en.wikipedia.org/wiki/Linear_congruential_generator)."""

    def __init__(self, p, a, b, s):
        self.params = p, a, b
        self.seed = s
        self.block_size = p.bit_length()

    def getrandbits(self) -> bitarray:
        """Get `self.block_size` random bits."""
        p, a, b = self.params
        self.seed = (a * self.seed + b) % p
        return int2ba(self.seed, length=self.block_size)


def encrypt(plaintext: bitarray, prng: PRNG) -> bitarray:
    """Encrypt `plaintext` using provided `prng`."""
    # number of blocks needed
    n = (len(plaintext) + prng.block_size - 1) // prng.block_size
    assert n <= 3

    # get random bits from `prng`, treated as a key stream to be XORed
    # with the plaintext
    key_stream = sum([prng.getrandbits() for _ in range(n)], bitarray())

    return plaintext ^ key_stream[:len(plaintext)]


if __name__ == "__main__":
    # `p` is intended to be `getPrime(2020)`. However, freshly generating a new
    # 2020-bit prime for each connection is such a huge waste of resource.
    # Therefore, we decide to fix its value as below:
    p = 65211977220892089569045463186732539303158357084345674525019223922060296962955192052081340976238500998741557164071033324269809415343882851005134334321981343116646432559928036672509078986141816570500249363856922917569581176421339604790053954260199447256675764678917476537199601659744868522143168253773264342459882005081309642416969704634232160589082663834584255588529471102107918634517698293211047541926109452067190602960919204208686203253917293259455554341825327963925122844129780261774584303048218473988438617945144493997764310914009350053694972501833699765812965584451364828122672890270175800017700685562657

    from secret import flag
    plaintext = bitarray()
    plaintext.frombytes(flag.encode())

    from random import randint
    while True:
        prng = PRNG(p, *[randint(0, p - 1) for _ in range(3)])
        prefix = int2ba(int(input()), length=int(input()))
        ciphertext = encrypt(prefix + plaintext, prng)
        print(ba2int(ciphertext))
        print(len(ciphertext))
```

The oracle accept value and bit length of the `prefix`, and output the one time pad of `prefix + flag`, the key is generated from a given `PRNG`.

The `PRNG` is just a normal `Linear Congruential Generator`. Look closer the prime $p$, we notice that the MSBs of $p$ are 0b10001.... Hence if a bitarray is generated from the `PRNG`, there's bias in the first bit of the bitarray (about 80% it will be 0). So we can use the bias to recover the flag bit-by-bit.

```python
from pwn import *
from bitarray import bitarray
from bitarray.util import ba2int, int2ba

io = remote("35.198.201.229", 1337)

flag = ''
for i in range(256):  # len(flag)
    alice = [0, 0]
    for j in range(10):
        io.sendline(b'0')
        io.sendline(str(2020 - i).encode())
        ct = int(io.recvline())
        l = int(io.recvline())
        ct = int2ba(ct, l)
        if ct[2020]:
            alice[1] += 1
        else:
            alice[0] += 1
    if alice[0] > alice[1]:
        flag += '0'
    else:
        flag += '1'
    if len(flag) % 8 == 0:
        print(int(flag,2).to_bytes(len(flag)//8, 'big'))
```

The flag is: `ASCIS{n0t_un1f0rmly_d1str1but3d}`

## Rijndael Ft. Arcfour

```python
from typing import List
import os
import aes  # https://github.com/boppreh/aes, added support for custom S-box.


def ksa(key: bytes) -> List[int]:
    """Arcfour (RC4) key scheduling algorithm."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        if i != j:
            # swap S[i] and S[j]
            S[i] += S[j]
            S[j] = S[i] - S[j]
            S[i] -= S[j]
    return S


def encrypt(msg: bytes, rc4_key: bytes, aes_key: bytes) -> bytes:
    """Rijndael (AES) ft. Arcfour (RC4) encryption routine."""
    sbox = ksa(rc4_key)

    # Since the sbox should look like a random table, we can check for weak
    # keys by counting the number of elements smaller than 128 in the first 128
    # entries. This number should be around 64.
    assert 64 - 8 <= [c < 128 for c in sbox[:128]].count(True) <= 64 + 8

    aes.set_s_box(sbox)
    iv = os.urandom(16)
    return iv + aes.AES(aes_key).encrypt_cbc(msg, iv)


if __name__ == '__main__':
    # give us a key
    key = bytes.fromhex(input())

    # here's a gift for you :)
    from secret import flag
    print(encrypt(f"The flag is: {flag}".encode(), key, os.urandom(16)).hex())
```

The oracle accept the input as the `rc4_key`, generate `S-box` from it and output the ciphertext.

Firstly, notice that for any `S-box`, we can always generate a `rc4_key` for it, hence the challenge become choosing a `S-box` such that we can decrypt the ciphertext without knowing the AES key.

Knowing that the `S-box` is the only part of `AES` that is not linear, so if we choose a linear `S-box`, the encryption become linear and we can decrypt the ciphertext easily with one pair of known plaintext-ciphertext, finally obtain the flag.

$$P_{i} + P_{0} = (C_{i} + C_{0})A$$

$$P_{i} = P_{0} + (C_{i} + C_{0})A$$

Where $A$ is some fixed 128x128 matrix, $P_{0}$ is known plaintext correspond to ciphertext $C_{0}$.

Full script:

```python
from sage.all import *

from typing import List
import os
import aes  # https://github.com/boppreh/aes, added support for custom S-box.

from pwn import *

def int2vec(n):
    return vector(GF(2), map(int, bin(n)[2:].zfill(8)))

def vec2int(v):
    return int(''.join(map(str, v)), 2)

def linear_sbox(a, b):
    s = [int2vec(_)*a for _ in range(256)]
    s = [vec2int(_) ^ int(b) for _ in s]
    return s

def sbox2key(sbox):
    key = []
    S = list(range(256))
    j = 0
    for i in range(256):
        k = S.index(sbox[i])
        key.append((k - j - S[i]) % 256)
        j = (j + S[i] + key[i]) % 256
        if i != j:
            # swap S[i] and S[j]
            S[i] += S[j]
            S[j] = S[i] - S[j]
            S[i] -= S[j]
    return bytes(key)

def solve():
    def bytes2vec(b):
        assert len(b) == 16
        res = []
        for bb in b:
            res += list(map(int, bin(bb)[2:].zfill(8)))
        return vector(GF(2), res)

    def vec2bytes(v):
        v = list(v)
        assert len(v) == 128
        res = []
        for i in range(0, len(v), 8):
            res.append(int(''.join(map(str, v[i:i+8])), 2))
        return bytes(res)

    while True:
        a = random_matrix(GF(2), 8, 8)
        while a.rank() < 8:
            a = random_matrix(GF(2), 8, 8)
        my_sbox = linear_sbox(a, 0)
        if 64 - 8 <= [_ < 128 for _ in my_sbox[:128]].count(True) <= 64 + 8:
            break
    rc4_key = sbox2key(my_sbox)

    aes.set_s_box(my_sbox)

    obj = aes.AES(os.urandom(16))
    P = matrix(GF(2), 128, 128)
    C = matrix(GF(2), 128, 128)
    c0 = obj.encrypt_block(bytes(16))
    for i in range(128):
        P[i, i] = 1
        p = P.row(i)
        c = obj.encrypt_block(vec2bytes(p))
        C.set_row(i, bytes2vec(c) + bytes2vec(c0))
    A = C.inverse()*P

    # io = remote("abcxyz", "1337")  # forgot :D
    io = process(["python", "rijndael_ft_arcfour.py"])  # for local test
    io.sendline(rc4_key.hex())
    c = io.recvline().decode()
    io.close()

    c = bytes.fromhex(c)
    iv = c[:16]
    ct = c[16:]

    p0 = bytes2vec(b'The flag is: ASC') + bytes2vec(iv)
    c0 = bytes2vec(ct[:16])

    flag = b'The flag is: ASC'
    flag2 = b''
    ct = [ct[i:i+16] for i in range(0, len(ct), 16)]
    for i in range(2, 0, -1):
        if i > 0:
            tmp = p0 + (c0 + bytes2vec(ct[i]))*A + bytes2vec(ct[i-1])
        flag2 = vec2bytes(tmp) + flag2
    flag += flag2
    print(flag)

if __name__ == "__main__":
    solve()
```

The flag is: `ASCIS{th3_sb0x_sh0uld_b3_f1x3d}`