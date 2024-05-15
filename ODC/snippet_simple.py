from pwn import *
from sys import *

SERVER = "bin.training.offdef.it"
PORT = ""
BINARY = ""


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

if "--debug" in sys.argv:
     
    gdb.attach(r, """
        #breakpoints
        b* 
        c
        """)
    input("wait")


#code

r.interactive()

