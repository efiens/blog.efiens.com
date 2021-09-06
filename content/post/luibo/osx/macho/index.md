---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Overview of Mach-O binary"
subtitle: ""
summary: ""
authors: [luibo]
tags: [osx, iOS, macOS, dyld]
categories: [osx]
date: 2021-09-06T11:15:01+07:00
lastmod: 2021-09-06T11:15:01+07:00
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

Mach-O is a binary format used by Apple for its systems. The binary format contains assembled bytes, data and other information. Structured by a list of load commands, where each load command hold the neccessary pointers to the contents.

## Header

At offset 0 lies a header structure, `struct mach_header`, containing the general information about the the binary.

```
struct mach_header {
    uint32_t magic;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;`
    uint32_t sizeofcmds;
    uint32_t flags;
};
```

Valid `magic` values are: `0xfeedface` for 32-bit format, `0xfeedfacf` for 64-bit format, little endian wise, big endian version are bytes swapped.

`cputype` and `cpusubtype` declare on which platform can this binary be loaded (or which assembly type this file contains). The most we are gonna see are x86, x86_64, and arm64, arm64e; while arm 32-bit aka armv7 (armv7s, armv7a) exist, Apple dropped support for these platforms since the release of iPhone 6.

`filetype` denotes the type of binary, *executable*, *dynamic library*, *object file*.

`ncmds` and `sizeofcmds` declare the number of load commands and the total size of load commands in byte. The reason why the size is required because the size of load command types varied. Also, the `sizeofcmds` is checked upon binary load, and throws error if it's incorrect.

`flags` is bit mask value for extra information, e.g. PIE.

## Load command

Each load command is structured, type of `cmd`, command size `cmdsize`, and information of that command.

There are many types of load commands, however we only focus on `segment`, `dynamic library`, `symbols`, `fairplay`, `codesignature` command types.

Segments are common in executable/library binaries. These point to the data inside where the `.text` or `.data` reside. In Mach-O binaries, a segment load command is followed by a series of sections, with each section mark the start/end of the data. The common sections are: `__text`, `__cstring`, `__const`, `__got`, `__la_symbol_ptr`, `__mod_init_func`, `__data`, `__bss`. These sections can be named without any restrictions, however compilers often name them by a rule of thumb. The attributes for the sections is marked with bit mask `flag`, indicating the attributes of the items.

A unique segment with no section is named `__LINKEDIT`. This section points to the last part of the binary containing various information, including tables of symbols, tables of symbols name, list of exported symbols, and binary's signature.

Each dynamic library is registered through a load command containing the path to the library. The path can either be absolute or relative. Absolute path resolving is straight-forward. With relative path resolving, the binary can use either of the two forms: relative to current directory, or **rpath**. Relative path with the current directory is easy to understand, `./`, `../` and such paths are valid in this case.

**rpath** is a little different, in short, the path started with either these variables: `@executable_path`, `@loader_path`, `@rpath`. `@executable_path` is replaced with the executable's residing folder, `@loader_path` is replaced with the path of the folder containing the loader. `@rpath` is resolve by `rpath` load commands.

The Mach-O binary can possess many load command to denote the `rpath`, each of the item must be an absolute path, or relative path, or using `@executable_path` or `@loader_path` or `@rpath`. It is unclear whether `rpath` can be stacked, but as a rule of thumb, we should not use `@rpath` on rpath load command. A common rpath often used by Apple is `@executable_path/Frameworks`, which can be seen on iPhone/iPad application binaries compiled using Xcode.

Fairplay encryption is a mechanism designed by Apple to encrypt the app content with the device private key, such that you cannot run the app from another machine. The Mach-O binary always have a load command pointing to the section starts and end, and the encryption status.

Due to Apple design of the fairplay, we can't recover the key to decrypt. However, we can actively dump the binary on memory, as it must be decrypted before running. Another method involves using the Apple mmap for fairplay encrypted region. These should be discussed on [[Fairplay]].

Codesignature is present on signed binary, using `codesign` with a `distribution` or `development` key. The sections tells us many informatin regarding the signer, and hashes. The signature is encoded in a PKCS#7/CMS with SignedData encoded in BER of ASN.1 (X.609). It also contains the list of certificates in X.509 format, and the signature digest. Currently Apple is using RSA to sign its binary.

The binary must be signed with a certificate chain root as Apple CA, otherwise Apple devices reject installation. Apps distributed through the Apple Store is also signed by Apple Store and device distribution certificate. For self-signed binary, the Apple CA is still the root certificate, while the children are `developer` certificate.

Symbols are encoded as a series of bytecode, a load command is specified to mark the region of symbols. This command registers the placement of `non lazy`, `lazy`, `exported` symbols. `non lazy` symbols are searched and written into the `got` table when the binary is loaded, `lazy` symbols are searched through `plt`, `export` symbols are indexes/addresses into the function start.

`non lazy` and `lazy` symbols are encoded as **bind** opcode; `export` symbols are encoded as a prefix-`trie`. More detailed about these in [[Linker Info]].

The above paragraph states the current situation of Mach-O symbols encoding. However, a few years ago, this was not the case. Few years back (don't know when), they have a list of symbols and dynamic symbols in sperated commands. Thus in the newver version of Mach-O, they have a command id as, `LC_DYLD_INFO_ONLY`, which shows that it should not be used with the legacy list anymore. Loader crashes if this command is used with an non-empty list of (dynamic) symbols.

The Mach-O related structures can be found and read on Apple's `cctools` modules at `include/mach-o/loader.h`.
