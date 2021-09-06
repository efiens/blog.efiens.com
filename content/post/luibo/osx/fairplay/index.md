---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Apple Fairplay protection in Mach-O"
subtitle: ""
summary: ""
authors: [luibo]
tags: [osx, iOS, macOS, dyld]
categories: [osx]
date: 2021-09-06T11:15:04+07:00
lastmod: 2021-09-06T11:15:04+07:00
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
projects: ["osx", "binary-format"]
---

Fairplay encryption created by Apple to protect digial possession rights. Implemented with a custom chip set for encryption and decryption with a hardcoded key. It is still unknown how to extract the key from the hardware. But decryption is feasible given a root access to the device.

When an application is loaded, the encrypted fairplay section must be decrypted. If the decryption is success, the app can start running as normal. During the course of the app's uptime, the section is decrypted and stayed in memory.

If the memory can be dumped when the app is running, we can retrieve the file in its un-encrypted form. Using Apple APIs, we can get the mapped binary file in memory. With this, we can collect the decrypted region and write back to file.

The method is clear. However, we need to run code in the same space as the applications. The details on how to do this can be found on [[Injections]]. Right now, there are solutions:

- https://github.com/stefanesser/dumpdecrypted 
- https://github.com/AloneMonkey/frida-ios-dump
- https://github.com/BishopFox/bfdecrypt
- https://github.com/KJCracks/Clutch

There's also improvements to this decrypt technology. The first one being issuing fairplay `mremap_encrypted` to load the encrypted section only. https://github.com/JohnCoates/flexdecrypt

The second one is by using an exploit to read other process' memory space. https://github.com/DerekSelander/yacd. This method applies only on iOS 13 and above, but the good thing is, there is no need of jailbreak.

Given the current situation of Apple, fairplay decryption is no where near mitigated. Fairplay decryption is crucial for most analysis, as the app can't be viewed when encrypted. As of now, we can decrypt them using the above methods, atleast, until Apple hardens the process. But even so, we can still use lower devices to decrypt.
