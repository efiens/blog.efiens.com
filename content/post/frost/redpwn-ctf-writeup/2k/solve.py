import struct
from z3 import *
from pwn import *

with open("prog.bin", "rb") as f:
    opcodes = f.read()
    
opName = {1: "DUP", 2: "POP", 3: "CHECK", 0x10: "ADD", 0x11: "SUB", 0x12: "MUL", 0x13: "DIV", 0x14: "MOD", 0x15: "MUL_MOD", 0x16: "IS_EQ",
    0x17: "CMP_0", 0x20: "INPUT", 0x21: "PRINT", 0x22: "PUT", 0x30: "JMP", 0x31: "JZ", 0x32: "JNZ", 0x33: "JLZ", 0x34: "JGZ", 0x35: "JLEZ",
    0x36: "JGEZ", 0x40: "STACK_TO_ARR", 0x41: "ARR_TO_STACK", 0x50: "INC_ARR_PTR", 0x51: "DEC_ARR_PTR", 0x52: "ADD_ARR_PTR", 0x53: "SUB_ARR_PTR"} 

'''rip = 0
while rip < len(opcodes):
    op = opcodes[rip]
    
    if (op != 0x22):
        print(str(rip) + ":\t\t" + opName[op])
        rip += 1
    else:
        print(str(rip) + ":\t\t" + opName[op] + "\t\t" + str(struct.unpack("<H", opcodes[rip + 1:rip + 3])[0]))
        rip += 3
'''
flag = [BitVec("x%d"%(i), 16) for i in range(64)]
flagPos = 0

rip = 0
stack = []
numArr = [0]*76
s = Solver()
numArrPos = 0

while rip < len(opcodes):
    op = opcodes[rip]
    if op == 1:
        lastElement = stack[-1]
        stack.append(lastElement)
        rip += 1
    elif op == 2:
        stack.pop(-1)
        rip += 1
    elif op == 3:
        token = stack.pop()
        rip += 1
        break
    elif op == 0x10:
        a1 = stack.pop()
        a2 = stack.pop()
        try:
            stack.append(a1 + a2)
        except TypeError:
            #print(rip)
            stack.append(BitVecVal(a1,16) + ZeroExt(16, a2))
            #print(stack)
            #print(BitVecVal(a1,8))
        rip += 1
    elif op == 0x11:
        a1 = stack.pop()
        a2 = stack.pop()
        stack.append(a1 - a2)
        rip += 1
    elif op == 0x12:
        #print(rip)            
        a1 = stack.pop()
        a2 = stack.pop()
        stack.append(a1 * a2)
        rip += 1
    elif op == 0x13:
        a1 = stack.pop()
        a2 = stack.pop()
        stack.append(a1 / a2)
        rip += 1
    elif op == 0x14:
        a1 = stack.pop()
        a2 = stack.pop()
        stack.append(a1 % a2)
        rip += 1
    elif op == 0x15:
        a1 = stack.pop()
        a2 = stack.pop()
        a3 = stack.pop()
        mulMod = (SignExt(16, a3) * SignExt(16, a2)) % a1
        stack.append(Extract(15, 0, mulMod))
        rip += 1
    elif op == 0x16:
        a1 = stack.pop()
        a2 = stack.pop()
        stack.append(If(a1 == a2, BitVecVal(1, 16), BitVecVal(0, 16)))
        rip += 1
    elif op == 0x17:
        a1 = stack.pop()            
        stack.append(If(a1 == 0, BitVecVal(0, 16), If(a1 > 0, BitVecVal(1, 16), BitVecVal(-1, 16))))
        rip += 1
    elif op == 0x20:
        stack.append(flag[flagPos])
        flagPos += 1
        rip += 1
    elif op == 0x21:
        char = chr(stack.pop())
        print(char, end = "")
        rip += 1
    elif op == 0x22:
        num = struct.unpack("<H", opcodes[rip + 1:rip + 3])[0]
        stack.append(num)
        rip += 3
    elif op == 0x30:
        addr = stack.pop()
        rip = abs(addr)
    elif op == 0x31:
        addr = stack.pop()
        token = stack.pop()
        if addr == 4:
            s.add(token != 0)
            rip += 1
        elif token == 0:
            rip = addr
        else:
            rip += 1
    elif op == 0x32:
        addr = stack.pop()
        token = stack.pop()
        if addr == 4:
            s.add(token == 0)
            rip += 1
        elif token != 0:
            rip = addr
        else:
            rip += 1
        
    elif op == 0x33:
        addr = stack.pop()
        token = stack.pop()           
        if addr == 4:
            s.add(token >= 0)
            rip += 1
        if token < 0:
            rip = addr
        else:
            rip += 1
    elif op == 0x34:
        addr = stack.pop()
        token = stack.pop()
        if addr == 4:
            s.add(token <= 0)
            rip += 1    
        if token > 0:
            rip = addr
        else:
            rip += 1       
    elif op == 0x35:
        addr = stack.pop()
        token = stack.pop()
        if addr == 4:
            s.add(token > 0)
            rip += 1 
        elif token <= 0:
            rip = addr
        else:
            rip += 1
    elif op == 0x36:
        addr = stack.pop()
        token = stack.pop()
        if addr == 4:
            s.add(token < 0)
            rip += 1 
        elif token >= 0:
            rip = addr
        else:
            rip += 1
    elif op == 0x40:
        numArr[numArrPos] = stack.pop()
        rip += 1
    elif op == 0x41:
        stack.append(numArr[numArrPos])
        rip += 1
    elif op == 0x50:
        numArrPos += 1
        rip += 1
    elif op == 0x51:
        numArrPos -= 1
        rip += 1
    elif op == 0x52:
        numArrPos += stack.pop()
        rip += 1
    elif op == 0x53:
        numArrPos -= stack.pop()
        rip += 1
    else:
        print("ERROR")
        break
for i in flag:
    s.add(And(i >= 47, i <= 127))    #This is pure guessing

if s.check() == sat:
    m = s.model()
    result = [m[i].as_long() for i in flag]
    print(bytes(result))
    #r = remote("mc.ax", 31361)
    #r.sendline(bytes(result))
    #r.interactive()
   
#flag{kenken_is_just_z3_064c4}   
        
        
        
        