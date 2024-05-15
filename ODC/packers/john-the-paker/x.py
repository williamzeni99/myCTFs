from pwn import *
from sys import *
import z3.z3 as z3
import math

#first part
'''
After having patched the code I started debugging and reversing. There was 7 checks: 
the firsts two were on the structure of the flag -> flag{<<key>>} (easy to reproduce ;)
the third one was on the characters that have to be printable (easy till now)
the fourth one was a check that didn't consider the flag at all, so I could reproduce
the code and let it print this part of the flag
'''
def FUN_08049385(param_5):
    dVar1 = math.pow(float(param_5), 5.0)
    dVar2 = math.pow(float(param_5), 4.0)
    dVar3 = math.pow(float(param_5), 3.0)
    dVar4 = math.pow(float(param_5), 2.0)

    result = int((float(param_5) * 99.65 +
                  ((dVar3 * 45.83333358 + (dVar1 * 0.5166666688 - dVar2 * 8.125000037)) -
                   float(dVar4) * 109.875) + 84.0))

    return result

first_part_flag = 'flag{'
for i in range(1,7):
    first_part_flag += chr(FUN_08049385(i))

print(first_part_flag) # flag{packer

#second part
'''
the fith check was A PAIN IN THE ASS: literally NOTHING WORKED, angr and z3 were useless. 
I spent more or less 4hours trying to figure out a way to reproduce correctly the behaviour of
that portion of code without success. The problem was on the pow and sqrt operation on a bitvector. 
So, because nothing worked I had to start to MANUALLY look at the register EAX after the return of 
the call. Basically I tryed one byte (one new character) per time and looked when EAX was 1 and when
was 0 (1 it was ok, 0 has to be changed). In addiction some strange behaviours occured on the 0x11
element of the flag, because of the extra check on that letter. Ah yeah, there was also a & in the flag
that I couldn't find for a while beacuse OBVIOUSLY & is the concatenation of commands so to actually
insert & you have to put \& or \\&. BUT ANYWAY AFTER HOURS OF CRYING I FOUND: -4r3-1337&
'''

#third part
'''
this part was so easy I made it in minutes with z3. I just added all the constraint made in the
sixth check (the 7th one was on the length of the flag that must be 0x21). 
'''

BINARY = "./ghidra_patched"

flag = [z3.BitVec(f'flag_{i}', 8) for i in range(0x21)]
s = z3.Solver()

for x in flag: 
    s.append(x>0x20, x<0x7e) #characters must be printable

i=0
for x in "flag{packer-4r3-1337&": #first part of the flag must be this one
    s.append(flag[i]==ord(x))
    i+=1
s.append(flag[0x20]==ord('}')) #this must be the last character


DAT_0804a081 = [
    0x0B, 0x4C, 0x0F, 0x00, 0x01, 0x16, 0x10, 0x07,
    0x09, 0x38, 0x00, 0x00, 0x00
] #this are the 10 bytes to be xored found with ghidra at addr 0x0804a081
    
sVar1 = len(flag)-0x16

for i in range(sVar1):
    s.add(flag[i+0x14] ^ DAT_0804a081[i] == flag[i+0x15]) #here I reproduce the 6th check


if s.check() == z3.sat:
    model = s.model()
    flag_values = [model[f].as_long() for f in flag]
    flag_string = ''.join(chr(value) for value in flag_values)
    print("FLAG:",flag_string)
    
else:
    print("Nessuna soluzione finale trovata")

