from pwn import *
from sys import *
import z3.z3 as z3

BINARY = "./ghidra_patched"

flag = [z3.BitVec(f'flag_{i}', 8) for i in range(0x21)]
s = z3.Solver()

for x in flag: 
    s.append(x>0x20, x<0x7e) #characters must be printable

i=0
for x in "flag{": #first part of the flag must be this one
    s.append(flag[i]==ord(x))
    i+=1
#s.append(flag[len(flag)-1]==ord('}')) #this must be the last character


#first half after dump1
local_48 = [0xb4, 0xaf, 0x73, 0xec, 0x5b, 0x21, 0x8a, 0x98, 0xcf, 0x45, 0xf2, 0x65, 0xcb, 0xe5, 0x48, 0xef]
local_28 = [0xd2, 0xc3, 0x12, 0x8b, 0x20, 0x58, 0xba, 0xed, 0xbd, 0x1a, 0x9c, 0x56, 0xb3, 0x91, 0x17, 0x9c]

for i in range(0x10):
    s.add((flag[i] ^ local_48[i]) == local_28[i])

#second half after dump3
local_50 = [0x5d, 0xe5, 0x26, 0x1f, 0x7a, 0x99, 0xe9, 0xa0, 0xcb, 0x5e, 0x25, 0xd7, 0x04, 0xbe, 0x97, 0xf9]
local_54 = [0x6d, 0x89, 0x50, 0x2c, 0x25, 0xa8, 0x9a, 0x8e, 0xe5, 0x70, 0x5c, 0xe0, 0x69, 0x8d, 0xe1, 0x84]

for i in range(0x10):
    s.add((flag[i+0x10] ^ local_50[i]) == local_54[i])

if s.check() == z3.sat:
    model = s.model()
    flag_values = [model[f].as_long() for f in flag]
    flag_string = ''.join(chr(value) for value in flag_values)
    print("FLAG:",flag_string)
    
else:
    print("Nessuna soluzione finale trovata")


'''
this challenge was cool becuase the unpacking phase and the reversing phase are merged together. 
Basically, in the decode function there is a first half of the code that is decoding the second half.
So, you have look with gdb where the code brokes and where not. If you follow the flow you will understand
that at addr 0x0010136f the code starts to change from the one seen in ghidra. So what I have done was to dump
from there to the end of the function. By inspecting the dump with ghidra you can see there is
a first check on the flag, and then a strange memcopy if a strange condition is met (see patch1). 
What is happening is that when the first half of the flag is checked correctly a portion of memory is copied
at addr 0x0010136f and then the code jumps at the beginning of the decode function. 

So that memory is the new code that will be decoded by the first half of the function. 
With z3 I could get easily the first half of the key by a simple reverse. Then using the first half 
of the flag I could inspect the second half of the code with gdb. 

I dumped the second half of the code (patch3) and done a reversing again. 

NB: in order to access the actual addr you have to do the hardware breakpoint (you can do max 4 of them)

hb: è proprio quello che ti aspetti, si ferma l'esecuzione quando arriva all'indirizzo specificato

b: questo sostituisce l'istruzione all'indirizzo specificato con l'istruzione "cc" che triggera GDB
 che si ferma. Non funziona quando c'è unpacking perché appunto la unpacking routine va 
 a lavorare su questa istruzione 0xcc invece che su quella originale e quindi perdi il breakpoint

'''