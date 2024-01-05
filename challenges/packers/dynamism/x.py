from pwn import *
from sys import *
import z3.z3 as z3


toxorvalue= 0x4827c3baaa35c7cc #value xored with the flag
tocheck = [
    0x2648a0c1cd54abaa,
    0x3c46afcfde54b5ab,
    0x3178e2e5d05ba8a5, 
    0x3c78b7d5cd6ab2a3, 
    0x1740a2d6cc6aa2a4, 
    0x265ea7e5c75ab5aa, 
    0x3c4e9cc9cb4298ed, 
    0x35189cded854af93
] #last 8 hex values copied in step 1

flag=b''
for i in tocheck:
    xorvalue = i ^toxorvalue
    flag+= xorvalue.to_bytes(8, 'little')

print(flag)

'''
by looking at this code it was easy to understand that the real code needed
is downloaded from a server, executed and then deleted.
So I used wireshark to see which get the code makes and which response recives. 
I looked at the bytes recived and de-compiled with an online decompiler. There was
basically 3 download: 

1) the first one was strange, half of the code seems legit, half not. In the first half it seems it copies
somenthig to somewhere
2) this is a function that is xoring stuff in memory
3) the last one was like a check in the memory

after carefully analizing the code using gdb I understood that the 1) copies 9 hexadecimal values in the heap
2) makes the xor between the flag and the first hex downloaded and 3) checks if the xored values are the same
with the lasts 8 hex donwloaded at step 1. 

So I understood the flag was 64 bytes long and by reversing the xor it was easy retrive the flag. 
'''