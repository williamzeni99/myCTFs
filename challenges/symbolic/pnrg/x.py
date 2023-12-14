from pwn import *
from sys import *
import z3.z3 as z3 

SERVER = "bin.training.jinblack.it"
PORT = "2020"
BINARY = "./pnrg"


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

#code
def mag_3808(val):
    return z3.If(val==0,z3.BitVecVal(0x0, 32),  z3.BitVecVal(0x9908b0df, 32))



def genRandLong():
    global index
    global state
    uVar1 = 0
    uVar2 = 0
    local_14 = 0

    if (0x26f < index) or (index < 0):
        if (0x270 < index) or (index < 0):
            m_seedRand(0x1105)

        for local_14 in range(0xe3):
            uVar2 = state[local_14 + 1]
            state[local_14] = state[local_14 + 0x18d] ^ (z3.LShR(uVar2 & 0x7fffffff | state[local_14] & 0x80000000, 1)) ^ mag_3808(uVar2 & 1)

        while local_14 < 0x26f:
            uVar2 = state[local_14 + 1]
            state[local_14] = state[local_14 - 0xe3] ^ (z3.LShR(uVar2 & 0x7fffffff | state[local_14] & 0x80000000, 1)) ^ mag_3808(uVar2 & 1)
            local_14 += 1

        uVar2 = state[0]
        state[0x26f] = state[0x18c] ^ (z3.LShR(uVar2 & 0x7fffffff | state[0x26f] & 0x80000000, 1)) ^ mag_3808(uVar2 & 1)
        index = 0

    uVar2 = index
    index = uVar2 + 1
    uVar1 = state[uVar2] ^ z3.LShR(state[uVar2], 0xb)
    uVar1 ^= (uVar1 << 7) & 0x9d2c5680
    uVar1 ^= (uVar1 << 0xf) & 0xefc60000
    return uVar1 ^ z3.LShR(uVar1, 0x12)



def m_seedRand(seme):
    global state
    global index
    state[0] = seme & 0xFFFFFFFF
    index = 1
    while index < 0x270:
        state[index] = state[index - 1] * 0x17b5 & 0xFFFFFFFF
        index += 1


index = 0
sleep(0.5)
random_1001=int(r.recvuntil(b',')[:-1],16) #value read from bash

state = [0 for i in range(0x270)]
seed = z3.BitVec('seed', 32)
s = z3.Solver()

m_seedRand(seed)
print("waiting...")
for _ in range(1000):
    genRandLong()

x = genRandLong()

s.add(x == random_1001)

if s.check() == z3.sat:
    model = s.model()
    print(model)
    r.interactive()
    
else:
    print("Nessuna soluzione finale trovata")


'''
This challenge was "easy" but it took me several days because of my setup(there was a bug with
z3, as you can see I have to double link in the import or just use 'from z3 import *', change
the code accordingly with your setup). 

So what I did was to emulate the random generator by inspecting the binary. Basically in the bash
it was printed a hex number that was the 1001 iteration of a given random algorithm. Initialilly, 
an array of size 0x270 is initialized to 0 and then using a seed from /dev/random a new state is 
generated. From the new state the random number is generated. 

With the help of z3 I serched for the seed such that the 1001th iteration was equal to the 
one printed in the bash (as shown in line 79). If the model is satisfiable I can print the seed 
and use it.  
'''
