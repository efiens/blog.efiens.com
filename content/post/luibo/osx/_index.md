---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Mach-O binary index"
subtitle: ""
summary: ""
authors: [luibo]
tags: [osx, iOS, macOS, dyld]
categories: [binary-format, osx]
date: 2021-09-06T11:15:00+07:00
lastmod: 2021-09-06T11:15:00+07:00
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

The following posts will introduce you to the binary format used by Apple, Mach-O. We first learn the basic format (1), then diving deeper into the import and export tables, and how the loader (dyld) binds these symbols (2). We continue to explore how Apple signs the binary (3) and how Apple prevents copying apps (4).

I will keep the posts updated with what I've researched. Readers can see the list below for my current research target.

- methods to inject into the Mach-O binary by either modifying the binary or using tools such as Frida (5).
- Obj-C class-dump
- Obj-C runtime
- Swift and Obj-C and C
- `__cstring` encryption (future work)

Series index:

1. [Overview of Mach-O binary](macho)
2. [Mach-O linker information](linker-info)
3. Mach-O codesign data
4. [Apple Fairplay protection in Mach-O](fairplay)
5. [Injecting code into Mach-O](injection)

> References will be updated here

## References

- http://www.m4b.io/reverse/engineering/mach/binaries/2015/03/29/mach-binaries.html
- https://github.com/flier/rust-macho
- https://lief-project.github.io//doc/latest/api/cpp/macho.html
- https://malwareunicorn.org/workshops/macos_dylib_injection.html
- https://adrummond.net/posts/macho

Official sourcecode of Apple:

- https://opensource.apple.com/source/dyld/dyld-655.1.1/launch-cache/MachOTrie.hpp.auto.html
- https://opensource.apple.com/source/dyld/dyld-655.1.1/src/ImageLoaderMachOClassic.cpp.auto.html
- https://opensource.apple.com/source/cctools/cctools-973.0.1/include/mach-o/loader.h.auto.html
- https://opensource.apple.com/source/objc4/

Novel research:

- https://github.com/pwn0rz/fairplay_research

Redback, introduced in Blackhat Asia 2020, but no public source-code release:

- https://blog.cystack.net/static-binary-injection-with-high-level-code/
- https://groundx.io/redback/

Worth checking out:

- https://github.com/facebook/fishhook
- http://www.cycript.org/
- https://frida.re/
- https://git.saurik.com/
- https://github.com/jmpews/Dobby
- https://geosn0w.github.io/ 
- https://github.com/akemin-dayo/AppSync
- https://github.com/BishopFox/bfinject
- https://github.com/0xxd0/objc4

> I will probably do some jailbreak research to answer questions such as what is performed during jailbreak.

**The list below is auto-generated, please refer to the list above.**
