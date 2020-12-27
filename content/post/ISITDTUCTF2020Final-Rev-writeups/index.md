---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "[ISITDTUCTF2020] Keylogger, Game, Maze writeups"
subtitle: ""
summary: "Writeups for ISITDTUCTF 2020 Finals reversing challenges"
authors: [midas]
tags: []
categories: []
date: 2020-12-27T05:58:43-08:00
lastmod: 2020-12-27T05:58:43-08:00
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
All files can be found [here](https://github.com/LKMDang/Short-CTF-Writeups/tree/master/isitdtuctf2020final)

# Keylogger

## Introduction
**Given files:** `Launcher.exe`, `capture.pcapng`.

**Description:** `We are tracking a suspect in a gold robbery of 4 men, After a few days he had access to a public computer. We then analyzed that computer and found it a keylogger software that someone secretly installed earlier, Hope you can find out what the thief accessed, whom to contact, any information that could lead to evidence of the robbery. `

**Category:** Reverse engineering

**Summary:** This is a Windows PE reverse engineering challenge of a keylogger program. The program has a lot of faking techniques, and also implements a custom protocol that needs to be reversed. The challenge also contains some network forensics and steganography problems.

## TL;DR:
1. Analyze `Launcher.exe` => Dump `XblCloud.dll` with `SpyStudio`.
2. Analyze `capture.pcapng` => Get information about zip file, keylogs and big TCP stream.
3. Analyze `XblCloud.dll` => Parse keylogs => Not much information.
4. Analyze `XblCloud.dll` again => Decrypt big TCP stream into screenshot => Get hint about on-screen keyboard (OSK).
5. Get my own screenshot with OSK on it => Plot parsed mouse clicks => Get zip file password.
6. Extract zip file => Get flag.

## Analyzing Launcher.exe
The `Launcher.exe` executable file throws an error when being executed, then it seems like nothing happens after that. So I started to reverse it statically using IDA. The flow is quite simple: it first throws a fake error about missing a DLL, then clones itself using the name `XblAuthenticator.exe`, then decrypts some data and saves it under the name `XblCloud.dll`, all the files created by this program are somehow related to XBox stuffs, but most likely they are just fake names and fake strings. My teammates said that it also does something to the registry hive, but that information is unecessary for the solution. The most important thing then was to get the DLL file. I think it can be retrieved by reversing the decryption function and decrypting the data, but my teammate `@Edisc` used `SpyStudio` and dumped it out for me. So all I needed to do was to analyze the DLL file and the traffic capture file.

## First look at capture.pcapng
Before reversing the big DLL file, I took a look at the network traffic capture. One of the things that I like to do when analyzing a `pcap` file is to throw it into `Wireshark` and then use the `Follow TCP stream` functionality to skim through all the TCP streams. Here are the informations that I gathered from doing that:
- The user (or the keylogger, I didn't know yet) sent a zip file called `message.zip` containing `message.txt` to `c.unsafesector.com/upload` in TCP stream number 4. Dumping the zip file and trying to extract it, I found out that it is archived using an unknown password.
- TCP streams number 0, 1, 2, 5, 6, 7, 8, 9, 11, 12 are quite identical, it seems like they contain the logged key presses and got encoded as a protocol in some way.
- TCP stream number 10 is quite large, and I had no information about it yet.

Since the packets are likely to be encoded in a custom protocol, I moved on to investigate `XblCloud.dll` to reverse its encoding.

## Analyzing XblCloud.dll
Analyzing from `DllEntryPoint()` onward, I arrived at function `sub_180002370`, which makes a lot of calls to `GetAsyncKeyState()`, which means it is where the keys are logged. 

The first two `GetAsyncKeyState()` are called with parameters 1 and 2, respectively. Looking at Microsoft's [virtual key codes documentation](https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes), I knew that these are to log mouse clicks. I could also see that the X and Y coordinates of the cursor are encrypted by XORing with `0xCAFEFAAA`.

The next two `GetAsyncKeyState()` are called with parameters from `0x30 - 0x39` and `0x60 - 0x69`. Again looking at the documentation, these are the number keys from 0 to 9, with `0x30 - 0x39` being the normal keys and `0x60 - 0x69` being the numpad keys. Both of them are then added with a constant to map into the range of `0x96 - 0x9f`.

The next `GetAsyncKeyState()` is called with parameter from `0x41 - 0x5a`, these are uppercase characters from A to Z. The encoding here is subtracting by `0x7a`.

The last `GetAsyncKeyState()` is specifically for the whitespace character `0x20`, which is encoded into `0x86`.

Also in each of these encoding, I saw that a timestamp retrieved from `GetTickCount64()` and a sequence number that got incremented after every logged keys are included. There are also some other complex fields, but they are too complex to reverse, so I checked back at `Wireshark` to see if I could figure something out.

## Parsing the keylog
I used my instinct to make a lot of assumptions in this part, so don't get confused about how could I figured them out, it was just my instinct.

Starting by looking at TCP stream 0, I could see a repetitive pattern in it: there are a lot of sequence starting with `\x0a\xXX\x08`. The sequences start at the fifth byte of the stream, so the first 4 bytes are most likely be the length of the stream, and that can be easily verified.

Now let's take a look at the first sequence: 
```
0a 14 08 00 10 c2 a6 b6 c3 03 18 00 22 08 ff ff fe ca aa fa fe ca
```
I could see there are two `0xcafe` bytes in this sequence, so this is likely the result from the XORing with `0xCAFEFAAA` in the log of a mouse click. The first 3 bytes seem like a header of some sort. The fourth byte in these sequences gets incremented every sequence, starting from 0, so it must be the sequence number. The next 7 bytes are incremented a little bit after each sequence, so I assumed that they are the timestamp. For the next 3 bytes, I don't even know what they are. And finally the last 8 bytes are the encrypted X and Y coordinate of the cursor when the mouse is pressed. This way, I could already parse the mouse click sequences into sequence number, timestamp and coordinates:
```python
def parse(data):
    length = u32(data[0:4])
    data = data[4:]
    i = 0
    while i < length:
        if data[i:i+3] == b"\x0a\x14\x08":
            seq_num = data[i+3]
            timestamp = u64(data[i+4:i+11] + b"\0")
            point_x = u32(data[i+14:i+18]) ^ 0xCAFEFAAA
            point_y = u32(data[i+18:i+22]) ^ 0xCAFEFAAA
            print("{} \t {} \t Mouse x = {}, y = {}".format(seq_num, timestamp, point_x, point_y))
            i += 22
```
Let's take a look at a shorter sequence that comes later in the TCP stream:
```
0a 0e 08 02 10 9e fb b6 c3 03 18 02 22 02 df 29
```
Again, I assumed the first 3 bytes are header, the fourth byte is sequence number, the next 7 are timestamp, the next 3 are unknown. For the last 2, by trials and errors, I knew that the first of them is the encoded key code, and the second is unknown and unimportant. The code to parse these sequences:
```python
    elif data[i:i+3] == b"\x0a\x0e\x08":
        seq_num = data[i+3]
        timestamp = u64(data[i+4:i+11] + b"\0")
        key_enc = data[i+14]
        if key_enc >= 0x96  and key_enc <= 0x9f:
            key = chr(key_enc - 0x66)
        elif key_enc >= 0xbb  and key_enc <= 0xe0:
            key = chr(key_enc + 0x7a - 0x100)
        elif key_enc == 0x86:
            key = " "
        else:
            key = "unknown"
        print("{} \t {} \t Key = {}".format(seq_num, timestamp, key))
        i += 16
```
By using only these 2 functions to parse the streams that contain the keylog, it failed at some later sequences because their headers are different: `\x0a\x0f\x08` and `\x0a\x15\x08`. I investigated these and it is actually quite simple: they are still the sequences for key presses and mouse clicks, but because the sequence number is greater than 255 then, they need one more byte to represent it. These two can be parsed using the following code:
```python
    elif data[i:i+3] == b"\x0a\x0f\x08":
        seq_num = u16(data[i+3:i+5]) - 0x100
        timestamp = u64(data[i+5:i+12] + b'\0')
        key_enc = data[i+15]
        if key_enc >= 0x96  and key_enc <= 0x9f:
            key = chr(key_enc - 0x66)
        elif key_enc >= 0xbb  and key_enc <= 0xe0:
            key = chr(key_enc + 0x7a - 0x100)
        elif key_enc == 0x86:
            key = " "
        else:
            key = "unknown"
        print("{} \t {} \t Key = {}".format(seq_num, timestamp, key))
        i += 17

    elif data[i:i+3] == b"\x0a\x15\x08":
        seq_num = u16(data[i+3:i+5]) - 0x100
        timestamp = u64(data[i+5:i+12] + b'\0')
        point_x = u32(data[i+15:i+19]) ^ 0xCAFEFAAA
        point_y = u32(data[i+19:i+23]) ^ 0xCAFEFAAA
        print("{} \t {} \t Mouse x = {}, y = {}".format(seq_num, timestamp, point_x, point_y))
        clicks.append((point_x, point_y))
        i += 23
```
Okay, then I could parse the key log:
```
0        6759538558943760        Mouse x = 1365, y = 0
1        6759538560579088        Mouse x = 646, y = 601
2        6759538564505104        Key = Y
3        6759538564573968        Key = O
4        6759538564634640        Key = U
5        6759538564788240        Key = T
6        6759538573237520        Key = U
7        6759538573363216        Key = B
8        6759538573431824        Key = E
9        6759538574540816        Key = Y
...
440      6759538946316560        Mouse x = 322, y = 181
441      6759538946603536        Mouse x = 385, y = 234
442      6759538946773776        Mouse x = 265, y = 79
443      6759538947125776        Mouse x = 373, y = 145
444      6759538947303952        Mouse x = 378, y = 118
445      6759538947587088        Mouse x = 436, y = 171
446      6759538947883024        Mouse x = 281, y = 111
447      6759538948105232        Mouse x = 346, y = 176
```
It seems that the dudes who were using this computer were just googling for some weird currency stuffs on the Internet, nothing seemed interesting to me yet. So I moved on to see what information I could gather from the last unknown part of the pcap: the big TCP stream number 10.

## Back to XblCloud.dll
I went back to the DLL file to find where the big stream is sent. First off, I went back to the function that log the keys to find where is the function that actually sends the stuffs. It can be easily recognized at `sub_180001910` because it makes a bunch of calls to some WSA networking function. I didn't analyze this function at all, instead, I cross-referenced it and found out that it's also called at `sub_180001DD0`. 

The lower part of this function is quite identical to the function that logs the keys, so it seemed like I went in the right direction. Scrolling up to the top of the function, I realized that it makes some calls to `keybd_event()` and some other functions that interact with the clipboard. Some quick searches around the Microsoft docs again and I knew that this function generates a `PrtScr` key press to take a screenshot and retrieves it from the clipboard. The image is then encoded in the `jpeg` format, I got this information by googling these 2 constants `1284378190221622446i64` and `3383081795586128797i64` that appear in `sub_1800016B0`. Therefore, the big TCP stream is a `jpeg` image of the screenshot that got encrypted in some way.

## Decrypting the screenshot
The encryption routine is clearly shown in `sub_180001DD0`, but because it is decompiled into some weird `m128i_i64` fields, it is quite hard to read. This is where my instinct comes into play again, let's look at this block of code:
```C
    v13 = v11;
    if ( v11 < v10 )
    {
      v14 = &img_buf[v11 / 0x10u];
      v15 = v10 - v13;
      v16 = *(img_buf->m128i_i64 + v13);
      do
      {
        LOBYTE(v14->m128i_i64[0]) = BYTE1(v14->m128i_i64[0]) ^ v16;
        v14 = (v14 + 1);
        --v15;
        v16 = v14->m128i_i64[0];
      }
      while ( v15 );
    }
```
A bunch of weird variables and fields are referenced here, but let's ignore them and get a closer look: 
```C
LOBYTE(v14->m128i_i64[0])  =  BYTE1(v14->m128i_i64[0])  ^ v16;
v14 = (v14 + 1);
... 
v16 = v14->m128i_i64[0];
```
This looks like every bytes in the image gets XORed with its next byte, except the last one. So I wrote a script to try to decrypt it to see if my theory is correct:
```python
from malduck import *

data = bytearray(unhex(open("screenshot_enc.hex", "r").read().replace("\n", "")))

for i in  range(len(data) - 2, -1, -1):
    data[i] = data[i] ^ data[i+1]

open("screenshot.jpg", "wb").write(data)
```
It actually is, I found the string `JFIF` in the decrypted data, so then I just had to cut out the part that is the header of the stream and what's left is the screenshot that is sent over by the keylogger.

## Analyze the screenshot
The screenshot was taken and sent after the user searched for the google calculator app, and did something with the numbers, as we can see from the parsed keylog. Linking it with the description, this is actually the 4 thieves stealing some gold and then converted the value of the gold they stolen to VND and divided it by 4. 

At this point, because I saw the calculator and all the mouse clicks, I immediately thought of plotting all the mouse clicks onto the screenshot to find out what they did after calculating the money. All I found after that point was disappointment, because the only thing that the "thieves" did after calculating the money was randomly clicking on the screen, then searched for `hero of the storm WTF` and watched some funny video game vids. It was a brainfart by me because I completely forgot about the `message.zip` file. It was even worse of a brainfart because I already thought of an on-screen keyboard shenanigans at this point, but somehow I couldn't link it with the password of the zip file.

## Finding the zip password
When I cleared the fog in my head, I looked back at the start of the keylog: there were a lot of mouse clicks before they connected to `c.unsafesector.com`, and maybe this was where they typed the password. I used `OpenCV` to plot the clicks directly onto the screenshot, and I found out that they clicked the on-screen keyboard icon on the icon tray at the bottom right of the screen, then clicked some keys. The idea then was to have my own keyboard on the screen, take a screenshot and plot the clicks on it. Thanks to the decrypted screenshot, I knew the resolution of the targeted PC is `1366x768`. Therefore, I changed my own screen resolution to that, popped my own on-screen keyboard up (remember to use the OSK that comes with the icon on the tray, not the one that you can find by searching the system, they are different!). I took my screenshot and started to plot on it using `OpenCV` (the keyboard clicks happened at the 16th to 49th clicks in the log):
```python
cnt = 1
for i in  range(16, 50):
    img = cv2.imread("./keyboard.png")
    cv2.circle(img, clicks[i], 6, (0,0,255), -1)
    cv2.imwrite("./imgs/tmp{}.jpg".format(cnt), img)
    cnt += 1
```
But because they also switched to the number keyboard in between and press some numbers, I had to take 2 different screenshots and plot them separately:
```python
cnt = 1
for i in  range(16, 37):
    img = cv2.imread("./keyboard.png")
    cv2.circle(img, clicks[i], 6, (0,0,255), -1)
    cv2.imwrite("./imgs/tmp{}.jpg".format(cnt), img)
    cnt += 1

for i in  range(37, 50):
    img = cv2.imread("./keyboard2.png")
    cv2.circle(img, clicks[i], 6, (0,0,255), -1)
    cv2.imwrite("./imgs/tmp{}.jpg".format(cnt), img)
    cnt += 1
```
The password could be recovered as: `emergency password 641578642380`, but it still was incorrect. Therefore I asked the author of this challenge `@ks75vl` and he told me the there was actually one more key press before the first `e`, but I didn't found it (weird?), so I just used my instinct again and assumed that it was a `Shift` key. So the correct password could be: `Emergency password 641578642380`.

Using that password to extract the zip file, I got the txt file that contains the flag:
```
ISITDTU{___1m_back_Y0ur3_part_at_16_0599416__108_2075535___}
```
## Appendix
The script for parsing the keylogs and plotting the clicks is `parse_key.py`.

The script for decrypting the screenshot is `decrypt_screenshot.py`.


# Game

## Introduction
**Given files:** `Auto9Yin.2.72.17.zip` (download [here](https://github.com/CTF-STeam/ctf-writeups/blob/master/2020/ISITDTU%20Finals/game/Auto9Yin.2.72.17.zip)).

**Description:** Decrypt this: `C2BAC628EC275E5F9D64A403A57AF4E9880BA46AE78560CC0B26F6D630C93A5BC3153098F77E7A871FE7C7484F72F36BC42BFA9E0E331C186E33646BDC61C9F21958CBE5DC6468EB84676F99C2504BA7B8BA29463E9C481C1182C4A718D2E45EB2ACEA664D10249E8F34DDA801E5692ECB3E4E34375589D38CCE4018A004C7EC9C6805C27A2D37C45290C38F7D7CE679762567DB2FDD44309F74365C18310673F6B98D99A1A27E2204555B3D12113CC4C72B665548C3738BE2E310206A68E89A1E5BE492AC00ABC22ACA5099FDF7E1426D82AF89AF53D8A84255002D166352890DA2FE8881450D836FC95AE28C9F604ACB00D3CF95CB2AAF1445F0D1234DE1BAD13739E6D18B3D0718ABD10C259635B6`

**Category:** Reverse engineering

**Summary:** This is a real world reverse engineering problem of an online game's third-party module. This is a paid botting module that requires player to buy a key to gain access to its features. Our task is to reverse engineer the key check phase in order to decrypt the given key. The author also gives us a [link to download the actual game](http://cuuam.gosu.vn/tai-game.html) (which is 22GB in size!) and a [link to a video](https://www.youtube.com/watch?v=M-GNl2B6m7A) where he shows us how to install and use the `Auto9Yin` module.

## TL;DR:
1. *Optional:* Download the game, watch the video and test out the module itself.
2. Extract the module and investigate it => See a lot of DLLs.
3. Investigate the `lua` scripts => See some scripts that load `auto_main` and `auto_core`.
4. Analyze the corresponding DLLs (and some others) => See the same structure, only differ is in the encrypted part.
5. Decrypt the similar part => Get a `lua` function to decrypt the different parts.
6. Decrypt the different part in `auto_9yin.dll` => Get the `lua` script that has the encryption and decryption routine.
7. Use the script to decrypt the given key => Get flag.

## Optional: Install the game and Auto9Yin
Before the event even started, the author gave us a link to download the game itself, because the game would be too large to be downloaded on site. I downloaded the game the night before and tried to play with it for a bit. It is actually a real Chinese RPG that got translated into Vietnamese that has quite a large player base. The game itself is free-to-play, so I didn't know what do we have to crack yet, so I just kept it as it is.

The day after, in the competition, we are given this challenge. The author gives us a link where he demonstrates how to install the `Auto9Yin` module itself and how to activate it. To activate it, we have to buy a valid code and submit it into the game, then we will have access to various botting features. I label this section as *Optional* because actually, we don't need to install neither the game nor the module, all we have to do is decrypt the given key.

## First look into the module and the lua scripts
Extracting the given zip files, I ended up with a quite large folder. There is a `bin` folder inside of it which contains many DLL files, which is quite intimidating to look at. Therefore, I didn't start by looking into the DLLs, but instaed at the folder `lua` (because I have watched some game development video before and they like to do scripting in `lua`, so this folder might be interesting). In that folder, I saw some short `lua` scripts that load `auto_main` and `auto_core`, which are 2 of the DLLs in `bin`. So I continued by analyzing these 2 DLLs.

## Analyzing the DLLs
Opening the 2 mentioned DLLs in IDA, I saw that all the functions in them are similar, I also opened other DLLs as well, and they are all almost similar. The only difference between them is that in function `luaopen_auto_*()` (`*` is different for each DLL), the strings that look to be encrypted are different. `luaopen_auto_*()` first makes a call to `sub_10001130()`, so I analyzed this function first.

This function is similar accross all DLLs and has a repeated pattern: first copies an encrypted string to a buffer, call `sub_10001000()` on it, then calls `luaL_loadbuffer()` and `lua_pcall()`. By quickly doing some Google search, I knew that the 2 latter functions are just from an API to interact with `lua` from native code. As far as I know, `luaL_loadbuffer()` compiles a piece of lua code, then pushes it into the lua stack, and `lua_pcall()` pops and runs it. Therefore, `sub_10001000()` must be the function where it decrypts the encrypted buffer into `lua` code.

## Decrypting the similar encrypted part
The decryption routine in `sub_10001000()` is not hard to understand: it simply maps some specific characters in the string to other characters then subtracts it by 1, and keeps the rest unchanged. It is easy enough to re-implement in python:

```python
MAP = {'H':'!', 'U':'*', 'N':'>', 'G':')', 'X':'e', 'I':'j', 'O':'v', 'A':'u', 'W':' ', 'T':'#', 'M':'/', 'L':'-', 'Y':'{', 'Z':'(', 'J':':', 'P':'^', 'C':'|', 'Q':'\\'}

def decrypt(str):
    result = ""
    i = len(str) - 1
    while True:
        c = str[i]
        if c in MAP.keys():
            c = chr(ord(MAP[str[i]]) - 1)
        else:
            c = chr(ord(str[i]) - 1)
        result += c
        i -= 1
        if i < 0:
            break
    return result
```

Using this python function to decrypt the encrypted buffer, I obtained the code in `xingxiang.lua`, which is obfuscated in the way that each of its function is written on only one line. I asked my teammate `@pcback` to help me beautify the lua code and re-implement it in python:

```python
def axing(buff):
    return ''.join(chr(int(buff[i:i+2],16)-1) for i in range(0, len(buff), 2))

begin = [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' ]
last = [ 'x', 'u', 'h', 's', 'p', 'v', 'g', 'q', 'r', 'y', 'z', 'n', 'm', 'i', 'w','k']

def decr(buff):
    temp = buff[::]
    for i in range(16):
        temp = temp.replace(last[i], begin[i])
    return temp

def reveser(s):
    return s[::-1]

def axiang(buff):
    temp = buff.replace('5', 'z')
    temp = temp.replace('f', '5')
    temp = temp.replace('z', 'f')
    temp = buff.replace('6', 'z')
    temp = temp.replace('d', '6')
    temp = temp.replace('z', 'd')
    return temp

def xingxiang(s):
    return reveser(axing(axiang(decr(reveser(s)))))
```

I was done with `sub_10001130()`, so I returned to `luaopen_auto_*()`. The function then calls `sub_10001300()` on a lot of encrypted strings.

## Decrypting the different parts
This function is quite small. First it uses the same decryption routine that decrypts the `xingxiang` script on a small string to obtain the string `"xingxiang"`, then it uses some lua API functions on this string and on the encrypted parameter. I didn't look much into the documentation this time, because it is almost certain that it uses `xingxiang` to decrypt the encrypted parameter, so I simply used the python code for `xingxiang` above to decrypt all of `auto_main.dll` and `auto_core.dll`.

Disappointingly, decrypting these 2 DLLs only results in lua scripts that handle the in-game botting stuffs, there is no code in those scripts that take care of the key. My thought process then was to decrypt all of the DLLs to find what I seek. Of course though, I had to look at the DLLs that have the most interesting names first, so I instantly looked at `auto_9yin.dll`, and I did hit the jackpot.

## Running auto9_yin to decrypt the key
The decrypted lua code from `auto_9yin.dll` is well commented, and it is used to handle everything about the key. There is a decrypt function in there, so firstly, I asked `@pcback` again to recode it into python. However, because of some differences between lua and python, he didn't succeed in doing that this time, so I had to find another way to do it.

My solution was to run the lua script itself on the given key to get the flag. However, there were also some hiccups doing this:
- The script requires some packages that is loaded somewhere else and I didn't have them, so I simply tried to remove all the `require()` calls.
- Doing the above will result in the lua script missing the `hex` and the `bin` packages. 
- I googles for those, but I can't find `hex`, so I looked in the script to find where it is used, and found out that it is simply use to convert the hex representation of the key into bytes. Therefore, I can do this in python, copy the result into lua and get rid of `hex`.
- For `bit`, I found it on the Internet, so I simply copy and paste it into the same folder.

With the above setups, I could successfully run the lua script to get the flag:
```
danchoihephoco,1922762076,This key was used as a real world challenge for a cyber security contest (see https://www.facebook.com/isitdtu/). If you are owner of this product, please do not share or leak it, thanks a lot. ISITDTU{r34l_w0rd_1s_fUn_4nd_34sY_bUt_lu4_sUcKs}
```
*Note:* Actually I forgot the technique of "googling the constant" when I was onsite at the competition. If I did a quick google search of the `delta = 0x9E3779B9` value in the script, I would have known that this encryption is `XTEA` and not have to waste time trying to recode/run the lua script.

## Appendix
The script for decrypting both the similar and the different parts in DLLs is `decrypt.py`.

The decrypted `auto_9yin.dll` lua script is `auto_9yin.lua`

The `bit` package for lua is `bit.lua`.

The modified lua script to decrypt the key is `a.lua`.


# Maze

## Introduction
**Given file:** `maze.exe`.

**Category:** Reverse engineering

**Summary:** This is what I called an *algorithmic/mathematical* type of reverse engineering challenge. The program is simple: it asks for an input, checks if its correct and then decodes the flag based on the given input and prints it out. Our task is to reverse engineer the checking process.

## TL;DR:
1. Analyze the program => Learn that it takes in the input as a path to get to the destination in a maze and checks it.
2. Learn how the program actually stores the maze and checks the path.
3. Model the problem mathematically and use `z3` to solve it.
4. Adding constraints to z3: coordinates bound (1), don't go back (2), initial and final coordinates (3), valid moves (4). 
5. Let it run => Get flag.

## Analyzing the program to learn the checking algorithm
The program takes in an input string, then checks if its length is 34. If that's the case then it will iterate through our string character by character. It only accepts 4 characters: `U`, `D`, `L`, `R` corresponding to up, down, left and right.

Initially, it sets the coordinates to be `(3, 0)`, moving up will decrement the X coordinate, down will increment it, moving left will decrement the Y coordinate, right will increment it. The way it checks if a move is valid is as follow: It stores a large array of size 256 in data that contains only 0s and 1s. It indexes the array by `4 * (coord_X + 8 * coord_Y)` plus 0, 1, 2 or 3. That means this is an array of quadruples, each corresponds to one `(X, Y)` coordinates. The value of each element in the quadruples is either 0 or 1, with 0 being "invalid move" and 1 being "valid move", the order of the elements is `(up, down, left, right)`. Because the array is of size 256, there are 64 quadruples, and by the way it is indexed, I knew that the maze is `8x8`.

Finally, it checks if we end up at `(4, 7)`. If we do, it uses our given path to decrypt the flag and prints it out for us. So the only thing I needed to do is find the correct path.

## Modeling the problem
Because I just read some great writeups about very cool `z3` solutions for algorithmic challenges like this, my initial thought was to use `z3` to solve it (although I forgot one constraint when I was onsite and didn't solve it by using z3 but by using another kinda luck-based solution, but the way I modeled the problem was correct). Initially, I thought of treating every of the 34 moves in the path as a z3 variable and model it from there, but this was actually not good enough because I couldn't index the valid-move array with these variables. Therefore, I changed the variables to `(X, Y)` coordinates after every move, even though it makes the number of variables becomes 70 (2*35, because I also treat the initial coordinates as a variable for easier construction of equations), it makes it so much easier to write all the z3 equations this way.

With this type of modeling, we have the following constraints:
1. **Coordinate bound condition:** All `X` and `Y` must be within the `8x8` maze.
2. **Don't go back condition:** Never go back to a coordinates that has already been explored (this is what I forgot at the competition).
3. **Initial and final coordinates:** Starts at `(3, 0)` and ends at `(4, 7)`.
4. **Valid move condition:** This is the most complex condition, constructed by using the array in the program.

## Writing z3 equations
For all the values of X and Y, I used `IntVector` data type in z3 because my advisor `@cothan` said that `IntVector` actually helps z3 solve faster than normal array of `Int`.

The 1st and 3rd conditions are simple:

```python
# Coordinates condition
for i in range(CNT):
    s.add(And(X[i] >= 0, X[i] < 8))
    s.add(And(Y[i] >= 0, Y[i] < 8))
# Initial coordinate condition
s.add(And(X[0] == 3, Y[0] == 0))
# Final coordinate condition
s.add(And(X[34] == 4, Y[34] == 7))
```

The 2nd condition is also not hard, but needs a bit of thought put into it. If I simply say that every `(X, Y)` pair is strictly different from all others, it will create too much constraints for z3 to solve (*34!* constraints). Therefore, I think of a more clever way to say it: If at step *i*, we are at coordinates `(X_i, Y_i)`, then at step *i+2*, if we are at the same `X_i`, then we must be at a different `Y` than `Y_i`, and vice versa, we don't care about step *i+1* because it must be different from step *i* no matter what:

```python
# Don't go back condition
for i in range(2, CNT):
    s.add(If(X[i] == X[i-2], Y[i] != Y[i-2], True))
    s.add(If(Y[i] == Y[i-2], X[i] != X[i-2], True))
``` 

For the 3rd condition, the first big problem is that I couldn't index a normal python array using a z3 variable, z3 simply doesn't allow that. Googling this issue leads me to a solution as below, using the `Array` type in z3:

```python
MAZE = Array('MAZE', IntSort(), IntSort())
i = 0
for elem in maze:
    MAZE = Store(MAZE, i, elem)
    i = i + 1
```

This way, I could index the `MAZE` z3 array using the function `Select()`. The rest of the work is to check each element in the quadruple corresponds to the last coordinates, if it equals to 1, I add in a possibility for z3 (using `Or()`):

```python
for i in range(1, CNT):
    cond1 = If(Select(MAZE, 4 * (X[i-1] + 8 * Y[i-1]) + 2) == 1, And(X[i] == X[i-1] - 1, Y[i] == Y[i-1]), False)
    cond2 = If(Select(MAZE, 4 * (X[i-1] + 8 * Y[i-1]) + 3) == 1, And(X[i] == X[i-1] + 1, Y[i] == Y[i-1]), False)
    cond3 = If(Select(MAZE, 4 * (X[i-1] + 8 * Y[i-1]) + 0) == 1, And(X[i] == X[i-1], Y[i] == Y[i-1] - 1), False)
    cond4 = If(Select(MAZE, 4 * (X[i-1] + 8 * Y[i-1]) + 1) == 1, And(X[i] == X[i-1], Y[i] == Y[i-1] + 1), False)
    s.add(Or(cond1, cond2, cond3, cond4))
```

## Running the z3 solver
Those are all of the constrains that can be constructed from the model of our problem, the only small step left to do is to convert the list of X and Y in the result into moves (remember, the program takes in the path as input, not the coordinates). Running the script and wait for a bit gave me the correct path: `LLDRRDLLLDRDLDDDRRULURRULURRDDDLDR`.

Inputting this into the program, I got the flag:
```
flag{FLa9_I5_w41tIN9_foR_YoU_A7_th3_w@y_ouT}
```

## Appendix
The z3 script to solve the problem is `a.py`.
