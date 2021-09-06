---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Mach-O linker information"
subtitle: ""
summary: ""
authors: [luibo]
tags: [osx, iOS, macOS, dyld]
categories: [osx]
date: 2021-09-06T11:15:02+07:00
lastmod: 2021-09-06T11:15:02+07:00
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

Dynamic symbols in Mach-O binary are stored in a form of bytecode and exported symbols are encoded as a prefix-`trie`. For dynamic symbols, Mach-O also has a stud binding to resolve symbols, which is the same as `__got` and `__plt` section on ELF binaries.

## Dynamic symbols

The linker reads up on symbols table and perform binding when neccessary. We start by explaining the bytecodes and finish with the binding process.

We have 4 different bytecode arrays, `rebase`, `bind symbol`, `weak bind symbol`, and `lazy bind symbol`. All 4 arrays using the same set of bytecode and laid out continuously in binary, with the only difference is the usecase.

Each byte encodes an opcode and its parameter, `uint8_t v = opcode | imm`. Some opcode require an additional `uleb128` number, the number can be read from the next bytes (at most 7 bytes, due to uleb128 encoding). Some opcode require a string, encoded next to and end with `0x00`.

The opcode reads into a state, and the state mutates after every code read. Basically the opcode is a compressed table, where we read through each row. Every new row read is first copied from the previous row and then update the collumns.

Often the binary is loaded in memory with a PIE slice, due to ASLR. A number of constants address created at compile time is no longer correct. When this happens, loader reads up the `rebase` opcode and add up the address constants to a value of slice.

`bind symbol`, `weak bind symbol`, `lazy bind symbol` are decoded into a list of dynamic symbols. Each symbol has `dylib ordinal`, `segment index`, `name`, `address`. At the start of each row, `bind_done` is performed, which will find the `name` symbol from the library declared using load command at index `dylib ordinal` (count start at 1), and write the address of the function at `address`. `dylib ordinal` has special values of 0, -1, -2 to indicate the the special dynamic library.

### Binding process

The binding process happens when a symbol address is written into the memory to provide callback for the original code. This process exist because the symbols are undefined in compiled time, and only visible at runtime, yet the address of symbols are randomly located after each run.

To resolve this issue, Mach-O binary has a fake jump into the symbols. Where as the original code calls an imported symbols, `foo`, it actually calls to a function that redirect to the resolved address.

```asm
__text:
call foo_  ;; call foo, but with a holder

foo_:
load foo_addr_holder
call

foo_addr_holder:
0x000000
```

With the above scheme, the compiler can easily create a holder for the address and let the loader re-write the address at runtime. One draw-back to this scheme requires the loader to resolve all imported symbols' address holders. Result in a longer startup time. But Mach-O can also perform lazy binding, by following the below scheme.

```asm
__text:
call foo_ ;; call foo lazy

foo_:
load foo_addr_holder
call

foo_addr_holder:
foo_addr_resolver ;; re-writen by loader after resolving

foo_addr_resolver:
load foo_opcode_start_index ;; just a number
call loader_symbol_resolver
```

For lazy bind symbols, the Mach-O has a resolver for each lazy symbols, and the function is called on the first time calling. This function loads a number and call the resolver from the loader. When the loader resolver finished, the address holder of the lazy symbol is re-written to contain the address of the symbol.

The number that is passed into loader's resolver is the index into the row of the lazy bind symbol of the correspondent symbol.

In Mach-O, the section for address holder or `__nl_symbol_ptr` and `__la_symbol_ptr` for non lazy (first scheme) and lazy (second scheme) symbols, respectively. The resolver section is called `__stub_helper`. In Go generated binaries, non lazy symbols section is named `__got`.

## Exported symbols

`exported symbols` is encoded as a prefix-`trie`, where each node holds an export symbol. The symbol can be Regular, Weak, Reexport, or Stub. Regular symbol has an address field, which is the offset from Mach-O. The parsing of the trie is quite simple, but requires a little recursive writting. Apple also write the encoding process in the Mach-O headers.

For regular symbols, the offset collected is the file offset of the Mach-O. This way, when searching for the function the loader can easily calculate the address on memory. The trie can also speed up searching by only follow the branch that matches the symbol to be found.
