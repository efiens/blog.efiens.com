---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "An Introduction to Symbolic Execution"
subtitle: ""
summary: "In this post, I introduce you to a program analysis technique called Symbolic Execution, its components, an in-theory perfect symbolic execution engine, some late writeup on challenges that I've used this technique and lastly the ANGR binary analysis platform"
authors: [luibo]
tags: ["symbolic execution", "program analysis", "binary analysis", "writeup"]
categories: []
date: 2020-12-13T21:18:44+07:00
lastmod: 2020-12-13T21:18:44+07:00
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
projects: ["symbolic-execution"]
---
{{< toc >}}
# The problem
```c
1: void foobar(int a, int b) {
2:  int x = 1, y = 0;
3:  if (a != 0) {
4:    y = 3 + x;
5:    if (b == 0)
6:      x = 2 * (a + b)
7:  }
8:  assert(x - y != 0)
9: }
```
In the above code, we want to find values of a and b such that the assertion holds. There are many ways of finding a and b. A trial-and-error method may output the solution. Such method could be slow and inefficient. Another way to approach the problem is calculating the values of x and y at each code path.

Line 1, $a, b \in Z$

Line 2, $x = 1, y = 0$

Line 3, if $a = 0$, then the assertion is correct ($x = 1, y = 0, a = 0, b \in Z$).

Line 3, if $a \neq 0$, then $y = 3 + x = 3 + 1 = 4$.

Line 5, if $b \neq 0$, the assertion is correct ($x = 1, y = 4, a \neq 0, b = 0$)

Line 5, if $b = 0$, $x = 2 * (a + b)$. This yields assertion $2 * (a + b) - 4 \neq 0$. And pass the assertion only if $a + b \neq 2 | a \neq 0, b = 0$, which simplifies to $a = 2, b = 0$.

Here, we do not look at concrete values of a and b, instead we use a and b as mathematical symbols and give them a range of value ($Z$) to start off with and reduce down after each if/else statement. We only know the valid values of a and b after all statements are finished.

The using of a and b like mathematical symbols (x in "find x" exercises in highschool math) to find values satisfying condition(s) is the Symbolic part of "Symbolic Execution". Using these symbols and run through the code testing at each code path is Execution in "Symbolic Execution".

# Symbolic Execution Engine

A program that runs Symbolic Execution is called Symbolic Execution Engine. This program can run a given function or even a program and test whether the conditions are met. The program must use a kind of SMT Solver to create the Symbolic variables and later combine the constraints to solve for the Symbolic variables. Because going through all code paths is not feasible (path explosion) in general applications, these engines must develop and use exploration technique(s) to limit the runtime memory.

## Simulator/Emulator

One of the main components of the Engine is the Simulator/Emulator. The code/program to be proven must be run inside a simulator which assigns values to Symbolic variables and builds up the constraints. A good Simulator/Emulator will enable the Engine to inspect the variables at runtime and dynamically create Symbolic variables along with their constraints.

Simulator/Emulator are not limited to those run on binary and bytecode, they could be ones that execute on an AST or even a JIT engine. Symbolic Execution Engines only need to know the declarion of variables and the constraints related to these variables.

A simulator/emulator is not preferred in [KLEE](https://github.com/klee/klee), a LLVM-based Symbolic Execution Engine. KLEE builds the code with Symbolic variables and uses them to solve the constraints at runtime.

## SMT Solver

An indispensable component of a Symbolic Execution Engine, SMT Solver. SMT Solver is a constraints solving system, it provides Symbolic variables and solves the constraints to give each Symbolic variables a possible value.

A notable SMT Solver is the Z3 Theorem Prover.

```python
from z3 import *

s = Solver()
a = Int('a')
b = Int('b')

s.add(a > 2)
s.add(b < 5)
s.add(a + b == 6)

s.check()
s.model()
```
`Int a` and `Int b` is the Symbolic variables, we slowly add constraints to the `Solver s` and output the model. Symbolic Execution Engine works just like that, with a state manager and an exploration technique.


## Exploration Technique

Symbolic Execution Engine must explore the code to build up the constraints. Each time a branch is found, the code path splits into two or more.

> Consider if (a == X || b == Y || c == Z), how many branches do we have?

To solve this problem, many researches focus on exploration techniques to minize the memory needed for a successful run.

> I will update this after I have read about these techniques :(

## An In-theory Perfect Symbolic Execution Engine

With those 3 components, a perfect Symbolic Execution Engine relies on the perfection of those component.

For binaries, the Simulator/Emulator must be able to work with different binary formats and architectures. Binary format are limited (PE32, PE32+, ELF, Mach-O); however architectures may vary, and to work efficiently, we need an Intermediate Representation (IR).

For programming languages, a unified language is required to work accross languages without writing custom Engine for each language.

SMT Solver works with variables like Int, Float, but in languages like C where pointers are a valid types. Our Engine must handle the pointers to a Symbolic variable.

Exploration technique is critical for a good Engine, it should use minimal memory and can minize/reduce the state explored.


# CTF Challenges

I solved these challenges with my scripting skill. At that time, I did not know about Symbolic Execution. However, after having learnt about Symbolic Execution, I am able to reason about my approach and analyze my solving script in details.

## InCTF 2019 Easy-VM

I do not see any writeup on this problem, I don't know if this is a trivial one or a hard one. Here's my attempt to solve it using my scripting skill and now explain it using Symbolic Execution.

This challenge has two files, an excutable binary and an unknown format binary file. The executable uses control flow flattening to obfuscate the control flow; however, we can track the state variable to know the next instruction. The executable read the unknown format binary file and execute the instruction inside that file.

> Pardon me, it's been too long so I don't remember how the binary exactly works, I might rework the challenge to give a more indepth explaination in future update. I just my solve script as a pointer, so it might be wrong.

The unknown format binary file is a list of 8 bytes instruction/data packed tightly, with the first 4 bytes "bi0s" and second 4 bytes (??). There are 10 registers in the form of array and 9 global variables used across the program. This program also use an array of 10000 items (unsure type) for storing/loading data.

```python
class Program:

  def __init__(self):
    raw_bytes = open('crackme.i', 'rb').read()[8:]
    self.code = [ int.from_bytes(raw_bytes[i:i+8], byteorder='little') for i in range(0, len(raw_bytes), 8) ]
    self.register = [0 for i in range(10)]

    self.instruction = 0
    self.data_10 = 0
    self.data_6 = 0
    self.data_4 = 0
    self.data_7 = 0
    self.data_8 = 0
    self.data_3 = 0
    self.data_5 = 0
    self.data_11 = 0
    self.data_12 = 0
    self.code_data = [0 for i in range(10000)]
```
Each instruction are decoded as follows:

```python
  def decode(self, ins):
    self.instruction = ins;
    self.data_10 = ~(~ins | 0xF000FFFFFFFFFFFF) >> 52;
    self.data_6 = (ins & (ins ^ 0xFFF0FFFFFFFFFFFF)) >> 48;
    self.data_4 = (ins & (ins ^ 0xFFFF0FFFFFFFFFFF)) >> 44;
    self.data_7 = (ins & (ins ^ 0xFFFFF0FFFFFFFFFF)) >> 40;
    self.data_8 = ~(~ins | 0xFFFFFF0FFFFFFFFF) >> 36;
    self.data_3 = ~(~ins | 0xFFFFFFF000FFFFFF) >> 24;
    self.data_5 = ~(~ins | 0xFF000000);
    self.data_11 = (~(~ins | 0xFFFFFFF000FFFFFF) >> 24) // 5;

    if self.data_5 >= 0x10:
      self.data_5 = int(hex(self.data_5)[-2:], 16)
```
A global variable will be used to select the next code:

```python
      data_11 = self.data_11
      if data_11 == 0:
        self.switch_code2()
      elif data_11 == 1:
        self.switch_code3()
      elif data_11 == 2:
        self.switch_code1()
      else:
        print("invalid code?")
```

`switch_code1` and `switch_code3` select the operation based on `data_3`

```python
  def switch_code1(self):
    data_3 = self.data_3
    if data_3 == 10:
      return self.add()
    if data_3 == 11:
      print("end routine")
      return 1
    if data_3 == 12:
      return self.jump()
    if data_3 == 13:
      print("has_current_eip")
      return 1
    if data_3 == 14:
      return self.foo7()
    return 0

  def switch_code3(self):
    data_3 = self.data_3
    if data_3 == 5:
      return self.cmp()
    if data_3 == 6:
      return self.foo1()
    if data_3 == 7:
      return self.mul()
    if data_3 == 8:
      return self.shift_left()
    if data_3 == 9:
      return self.shift_right()
    return 0
```

`switch_code2` uses `data_3` for operation selection but also uses `data_4` for data input and output.

```python
  def switch_code2(self):
    data_3 = self.data_3
    data_4 = self.data_4
    register = self.register
    if data_3 == 0:
      return self.load()
    if data_3 == 1:
      return self.save()
    if data_3 == 2:
      register[data_4] = get_char()
      return 1
    if data_3 == 3:
      print(chr(register[data_4]))
      return 1
    if data_3 == 4:
      return self.mov()
    return 0
```

After learning that compare and jump are used to divert the flow to the wrong path, I know that we need to find a way to find a satisfying path for each input. I add a SMT solver, for each input, I create a Symbolic variable and for comparision, I add the constraints.

```python
    # __init__
    self.s = Solver()
    self.flag_count = 0
    self.vars = []

    ...

    # switch_code2
    if data_3 == 2:
      print("register[{}] = get_char()".format(data_4))
      register[data_4] = Int('flag_{:>3}'.format(self.flag_count))
      self.s.add(register[data_4] >= 0)
      self.s.add(register[data_4] <= 255)
      self.flag_count += 1
      return 1

  def cmp(self):
    data_4 = self.data_4
    data_7 = self.data_7
    data_6 = self.data_6
    register = self.register
    if data_6 == 0:
      print("register[{}] != register[{}]".format(data_7, data_4))
      print(register[data_4] == register[data_7])
      self.s.add(register[data_4] == register[data_7])
      return 1
    if data_6 == 1:
      print("register[{}] > register[{}]".format(data_7, data_4))
      print(register[data_4] <= register[data_7])
      self.s.add(register[data_4] <= register[data_7])
      return 1
    if data_6 == 2:
      print("register[{}] < register[{}]".format(data_7, data_4))
      print(register[data_4] >= register[data_7])
      self.s.add(register[data_4] >= register[data_7])
      return 1
    return 0
```

After that, I wrote code to simulate all other instructions. Solving the model yields us the flag:

`inctf{1_kN0w_1t5_R3411y_3z_&_fuNNy_but_1ts_h0n3st_w0rk!}`

The full code is [here](https://github.com/nganhkhoa/ctf-writeup/blob/master/2019/inctf/easy-vm/run.py).
Warning: bad code, will clean up someday.

## De1CTF 2020 Code Runner

There are 2 writeups on this challenge, both attempted with ANGR and solved it arround 10-20 seconds, which is slow. I wrote the simulator and apply symbolic execution manually. This reduces the runtime to less than 1 second.

The challenge gives an endpoint, when netcat to the endpoint, a simple proof of work challenge is presented, after passing the challenge, the server output a MIPS binary base64 encodeded and wait for the correct submission of the binary.

First I use elftools to get the code section of the binary, then use capstone to disassemble all the bytecode into a list of instructions.

```python
from capstone import *
from elftools.elf.elffile import ELFFile

def get_insn_list(bytecode, first_addr):
    insn_list = {}
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN)
    for insn in md.disasm(bytecode, first_addr):
        insn_list[insn.address] = (hex(insn.address), insn.mnemonic, insn.op_str, insn.size)
    return insn_list

f = ELFFile(open('code_runner', 'rb'))
symbols = f.get_section_by_name('.dynsym')
[main] = symbols.get_symbol_by_name('main')
text = f.get_section_by_name('.text')

first_addr = text['sh_addr']
check_start = 0x00401994

bytecode = text.data()
insn_list = get_insn_list(bytecode, first_addr)
```

Then starting at the first function we know each function uses four bytes for checking and proceed if the conditions are either true or false. The functions go in until the last function is met which has no check. Simulate the code is quite hard, we have to find the correct branch to jump into (because scripting is very hard to manage exploration states). I have to build the control flow graph for each function and detect the correct path to. To build the control flow graph, we first split the function by its terminated instruction (branch/jump) and put the instructions into blocks called basic blocks.

```python
class Node:
    def __init__(self, insn, next_func = None):
        self.insn = insn
        self.addr = insn[0][0]
        self.next_func = next_func
        (_, i, op) = insn[-1]
        if i == "b":
            self.branch = "branch"
            self.to = int(op, 16)
        elif i == "beq":
            self.branch = "equal"
            self.to = int(op.split(', ')[-1], 16)
        elif i == "bne":
            self.branch = "non_equal"
            self.to = int(op.split(', ')[-1], 16)
        else:
            self.branch = "return"
            self.to = None
        self.mustbe = None

def split_to_nodes(func):
    nodes = []
    insn = []
    next_func = None
    for (addr, i, op) in func:
        insn += [(addr, i, op)]
        if i == "jal":
            next_func = int(op, 16)
        if i == "b" or i == "beq" or i == "bne" or i == "jr":
            nodes += [Node(insn, next_func)]
            next_func = None
            insn = []
    return nodes
```

After having the control flow graph, I follow the branch instruction that `mustbe` made and add constraints based on that. Now I only need to simulate the rest of MIPS code to add Symbolic variables and build up the constraints as the code simulate.

```python
    def condition(self, z, param):
        # PIndex is the index to input character
        # I don't know why I created a class for the index
        reg = {}
        reg["$zero"] = 0
        reg["$sp"] = 0
        for (_, i, op) in self.insn:
            # print(i, op)
            if i in ["sw", "nop", "jal", "negu", "b"]:
                pass
            elif i == "move":
                [out, x] = op.split(', ')
                reg[out] = reg[x]
            elif i == "lw":
                [out, x] = op.split(', ')
                if x == "0x20($fp)":
                    reg[out] = PIndex()
            elif i == "lbu":
                [out, x] = op.replace(')', '').replace('(', '').split(', ')
                reg[out] = param[reg[x].v]
            elif i == "addiu":
                [a, b, c] = op.split(', ')
                reg[a] = reg[b] + int(c, 16)
            elif i == "addu":
                [a, b, c] = op.split(', ')
                reg[a] = reg[b] + reg[c]
            elif i == "subu":
                [a, b, c] = op.split(', ')
                reg[a] = reg[b] - reg[c]
            elif i == "xor":
                [a, b, c] = op.split(', ')
                reg[a] = reg[b] ^ reg[c]
            elif i == "andi":
                [a, b, c] = op.split(', ')
                reg[a] = reg[b] & int(c, 16)
            elif i == "sll":
                [a, b, c] = op.split(', ')
                reg[a] = reg[b] << int(c, 16)
            elif i == "mult":
                [a, b] = op.split(', ')
                reg["hi"] = reg[a] * reg[b]
                reg["lo"] = reg[a] * reg[b]
            elif i == "mflo":
                reg[op] = reg["hi"]
            elif i == "bgez":
                [a, _] = op.split(', ')
                reg[a] = If(reg[a] > 0, reg[a], -reg[a])
            elif i == "slt":
                [a, b, c] = op.split(', ')
                reg[a] = If(reg[b] <= reg[c], 1, 0)
            elif i == "bnez":
                [a, _] = op.split(', ')
                if self.mustbe == True:
                    z.add(reg[a] == 0)
                elif self.mustbe == False:
                    z.add(reg[a] != 0)
                print(z)
            elif i == "bne" or i == "beq":
                [a, b, c] = op.split(', ')
                if self.mustbe == True:
                    z.add(reg[a] == reg[b])
                elif self.mustbe == False:
                    z.add(reg[a] != reg[b])
                print(z)
            else:
                input("unknown instruction")
```

Because the function is a chain of calls to functions, I just keep running until the last function is met

```python
def do_next(insn_list, start = check_start):
    print(hex(start))
    nodes = split_to_nodes(dump_func(insn_list, start))
    inspect_badjump(nodes)
    next_func = None
    z = Solver()
    param = [BitVec(f"param_{i}", 8) for i in range(4)]
    for n in nodes:
        # print(n)
        if n.next_func:
            next_func = n.next_func
            if hex(start) == "0x4013c8":
                n.mustbe = False
                n.condition(z, param)
        else:
            n.condition(z, param)
    z.check()
    m = z.model()
    r = sorted([(d, m[d]) for d in m], key = lambda x: str(x[0]))
    flag = list(map(lambda x: int(str(x[1])), r))
    print(flag)
    print()
    if next_func:
        return flag + do_next(insn_list, next_func)
    return flag
```
And the correct answer is:

```python
answer = do_next(insn_list)
print(answer)
```

You might have noticed already, the start function is hard-coded. This is our team mistake (including me). We thought that there is only ONE binary, I solve only one binary. When the CTF is over, I read the writeup and found out that the binary downloaded is different each time we connect to the server. I don't know if I have the correct general answer, but the script I wrote generate the correct answer for the binary I have. If something has to be changed, than I need to find the first check function automatically.

> It seems that the function at `0x4013c8` has a different `mustbe` than other functions. I didn't remember, but I think I should recheck the `mustbe` value of each function.

> I will update the qemu-mips running here with the output generated from our code in the future

Our solution surpasses the runtime using ANGR and also not ad-hoc like other wirteups. By using symbolic execution, we can write a more general solution to the problem.


Full code and binary is [here](https://github.com/nganhkhoa/ctf-writeup/blob/master/2020/de1ctf/code_runner/code_runner.py). Again, bad code warning.


## What I miss from these writeups

Symbolic Execution Engine needs a very good state manager, because each time a branch is made, the state (atleast) doubles. Hand crafted solver like these two writeups doesn't rely on a state manager because we assume a code path that must be chosen. In real life scenario, code path are undecidable and require the Engine to select the good path, remove the bad path. Most research on Symbolic Execution is about Exploration Technique because a good algorithm saves the memory and time running a solution.


## References:

To be updated
