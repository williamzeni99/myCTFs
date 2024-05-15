from pwn import *
from sys import *

SERVER = "bin.training.offdef.it"
PORT = "4004"
BINARY = "./master_of_notes"


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

if "--debug" in sys.argv: 
    gdb.attach(r, """
        #breakpoints
        c
        """)
    input("wait")


#code

chain = [ ]

def load_stack(value):
    #write how to write 32 or 64 bit data on stack
    print("gay")

def pushchain(chain):
    for i in chain: 
        load_stack(i)


pushchain(chain)
r.interactive()