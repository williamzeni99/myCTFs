from pwn import *
from sys import *
import z3.z3 as z3

BINARY = "./binary"
FLAG_LEN = 0x21

flag = [z3.BitVec(f'flag_{i}', 8) for i in range(FLAG_LEN)]
s = z3.Solver()

for x in flag: 
    s.append(x>0x20, x<0x7e) #characters must be printable

i=0
for x in "flag{": #first part of the flag must be this one
    s.append(flag[i]==ord(x))
    i+=1
s.append(flag[len(flag)-1]==ord('}')) #this must be the last character REMOVE if you are not sure of the len



if s.check() == z3.sat:
    model = s.model()
    flag_values = [model[f].as_long() for f in flag]
    flag_string = ''.join(chr(value) for value in flag_values)
    print("FLAG:",flag_string)
    
else:
    print("Nessuna soluzione finale trovata")