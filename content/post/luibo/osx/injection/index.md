---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Injecting code into Mach-O"
subtitle: ""
summary: ""
authors: [luibo]
tags: [osx, iOS, macOS, dyld]
categories: [osx]
date: 2021-09-06T11:15:05+07:00
lastmod: 2021-09-06T11:15:05+07:00
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

This article introduces the reader to some easy injection that can be used to hijack the runtime of a Mach-O binary. Some techniques can be easy to perform, some are posible due to 3rd party toolings, and some are based on theory.

## Before start

Apple's loader loads and run all initial functions from dynamically linked libraries. Due to this, we can create functions that run before the main binary is started. With a little craft, we can also make our functions the first function to be run.

Started by making a dynamic library (`*.dylib`) with functions we wish to run in loader state as:

```c
struct ProgramVars {
  void*	mh; // mach_header or mach_header64
  int*		NXArgcPtr;
  const char***	NXArgvPtr;
  const char***	environPtr;
  const char**	__prognamePtr;
};


__attribute__((constructor))
void foo(int argc, const char** argv, const char** envp, const char** apple, struct ProgramVars* pvars) {
// code goes here
}
```

`__attribute__((constructor))` marks the compiler to place the function address into `__mod_init_func`, a section dedicated to be called by loader when the binary is loaded.

With this library compiled, we can run `foo` before the main binary is run by using these few methods.

## DYLD_INSERT_LIBRARIES

Similar to `LD_PRELOAD` on Linux OSes, `DYLD_INSERT_LIBRARIES` is read by loader and load addional libraries provided in value. This method is easy to do when working on MacOS, but impossible for system where we don't have access to terminal, legacy iOS, tvOS, watchOS.

## Adding load command

If we have a Mach-O binary, we can add another load command to make loader to find and load the library, which follows calling our library initial functions.

In most cases, Mach-O binary has a spare space between the list of load commands and the contents. We add a load command in this empty space, fix the header with new `ncmds` and `sizeofcmds`.

After that everything is set, we resign the binary (if iOS/tvOS/watchOS) and install. On run, loader loads and runs our functions before the main binary.

This method can be extended to make the function run first, but requires a very careful crafting.

As loader load each library following the order of their declaration in the main Mach-O binary. If we can move our library first, we can make our functions the very first to run.

Fixing the ordering of load commands can be done easily, but just fixing them won't work. As the opcodes to dynamic symbols are encoded with the library ordering. E.g. a symbol `printf` referencing library indexed `1` now must reference `2`, because we've pushed our library on top. And it gets worse, since the `__stub_helper` index into the opcode bytestream. Which means if we edit the bytestream and somehow mess up with the order, we fail.

### Fixing opcodes?

This section delivers an in depth analysis of this scenario. In the opcode bytestream, there are two opcode to encode the library index (we don't count the special index as it is defined in different opcode): `BIND_OPCODE_SET_DYLIB_ORDINAL_IMM` and `BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB`. To prevent long names, we call them `imm dylib` and `uleb dylib`, respectively.

Opcode using `imm dylib` will be 1 byte and apply for libraries with indexed not exceeding 15 (0xf is max).

Opcode using `uleb dylib` will be 2 bytes or more, where the first byte is the opcode, and the rest bytes are index encoded in uleb128.

Problem occurs when a `imm dylib` with index 15 is increased, which turns the number to 16 and have to encode using `uleb dylib`. Which breaks the index in `__stub_helper` for other symbols. When this is problematic event occurs, we can resolve these by many ways, I haven't tested these solution but in theory it should work.

1. Fixing `__stub_helper`

Straight forward solution, we update the new index to the symbols in opcode bytestream to the `__stub_helper`. We know which stub points to which symbol before the edit, after editing, just loop through each stub and update the new index.

2. Fixing it on runtime

This is harder and prone to crashing. Because we can inject our function before the main code is run, we add a resolver for these symbols. There are plenty ways to do this, depends on how creative you are and how brave are you to tackle these solutions.

Remarks: `__stub_helper` can't be edited on runtime, but the `__la_symbol_ptr`, which holds the address for each function (default to stub) can be edited on runtime. We abuse this.

`__la_symbol_ptr` doesn't show us which symbols is being called, however, we match the information with stub's old index to identify the symbol.

```
__la_symbol_ptr:
stub_1
stub_2

stub_1:
load index_1
call bind

stub_2:
load index_2
call bind


;; index 1 is foo of libA
;; index 2 is bar of libB
;;
;; __la_symbol_ptr = [foo of libA, bar of libB]
```

- Simulate the loader

On load, we updates the whole `__la_symbol_ptr` sections with symbols' address. We use Apple's API to find all loaded libraries, and traverse the export trie to find the function address.

> similar to overwrite `__got`, `__plt` in pwn technique

```c
struct Symbol {
  char * name;
  char * lib;
  void * address = 0;
}

struct export_trie;
void* find_symbol_address(export_trie* exported);
export_trie* get_export_trie(void* header); // mach_header or mach_header64

void update_symbols_in_lib(Symbol* symbols, char * lib, export_trie *
  exported) {
  for (unsigned int i; i < len(symbols); i++) {
    if (strcmp(symbols[i].lib, lib) == 0) {
        void* addr = exported.find_symbol_address(symbols[i].name);
        symbols[i].address = addr;
    }
  }
}

// not test, quick way to get la_symbol_ptr section pointer
// static volatile void* la_symbol_ptr __attribute__((section ("__DATA,__la_symbol_ptr"))) = { 0 };

void resolve() {
  Symbol* to_bind = read_la_symbol_ptr();
  for (uint32_t i; i < _dyld_image_count(); i++) {
    void * header = _dyld_get_image_header(i);
    char * lib = _dyld_get_image_name(i);
    export_trie* exported = get_export_trie(header);
    update_symbols_in_lib(to_bind, lib, exported);
  }
}
```

- Hijack `dyld_stub_binder`

`dyld_stub_binder` holds the address to loader's bind method. Conveniently, this symbol resides in `__got`/`__nl_symbol_ptr`, which got resolved when the binary is loaded.

When our function run, we can rewrite this value to our custom function. Which will get call by other stubs. We now know the original index passed by stubs, we just need to change the old index to new ones and send to the original bind method. This seems easier to implement.

```c
void* find_original_bind() {
  // read __nl_symbol_ptr or __got
  // to find original dyld_stub_binder
  // should be the first one (iirc)
}

// original bind function receives two parameter,
// first is index
// second is cache of libraries (iirc)
void custom_bind(int old_index, void* param) {
  static void(*original_bind)(int, void*) = (/* cast */)find_original_bind();
  int new_index = get_new_index(old_index);
  original_bind(new_index, param);
}
```

## Cycript

Probably the first injection framework on iOS, but stopped development since 2016. Created by one of the most renowned jailbroken iOS developer, the creator of Cydia, Jay Freeman or commonly known as *saurik*.

At the latest version, Cycript supports til iOS 11. More information can be found publicy on their [website](http://www.cycript.org/).

## Frida

Frida is famously known for its injection ecosystem that works seemlessly across Android, Apple OS, Windows, Linux. To setup Apple device with Frida is easy and instrumentation, hijacking code can be done just by writing a piece of Javascript code.

The following guide is provided only for iOS devices.

### Setup

The setup of Frida is different between non-jailbroken and jailbroken devices.

For jailbroken devices, a server must be installed and run. Then frida (on PC/Mac) can connect through the usb cable and ask the server to perform tasks such as querying the system files, listing apps, start an app, hook a running app...

For non-jailbroken devices, if Frida < 12.7.12 is used, we must manually add the Frida dynamic library (FridaGadget) to the binary. The Frida documentation says that for Frida >= 12.7.12, FridaGadget is automatically injected, but I haven't tested, and doubt that it works with iOS (due to codesigning and restriction in environment).

### Inject then Hijack

I put simple script for reference. There are plenty on the Internet.

```js
// normal attach to inject onEnter and onExit
// demo CCCrypt module
Interceptor.attach(
  Process.getModuleByName('libcommonCrypto.dylib').getExportByName('CCCrypt'),
  {
    onEnter(args) {
      let algorithm = (function(algo) {
        if (algo === 0) return "AES128";
        if (algo === 1) return "DES";
        if (algo === 2) return "3DES";
        if (algo === 3) return "CAST";
        if (algo === 4) return "RC4";
        if (algo === 5) return "RC2";
        return "algo_" + algo;
      })(args[1].toInt32())

      console.log("CCCrypt using " + algorithm)
      console.log("CCCrypt key:")
      console.log(args[3].readByteArray(args[4].toInt32()))
      console.log("CCCrypt iv:")
      console.log(args[5].readByteArray(16))
      console.log("CCCrypt => " + args[6].readUtf8String())
    }
  }
)

// inject on an address of a lib or main binary
let module = Process.getModuleByName(module_name)
let offset = 0x1234 // reverse engineer
Interceptor.attach(SF.base.add(offset), {
  onEnter() {
    // accessing registers
    // console.log("Calling x9 raw: " + this.context.x9)
  }
})
```

## bfinject

> Easy dylib injection for jailbroken 64-bit iOS 11.0 - 11.1.2. Compatible with Electra and LiberiOS jailbreaks

Update soon(tm)
