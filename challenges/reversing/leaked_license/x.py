from pwn import *

SERVER = ""
PORT = ""
BINARY = "./leaked_license"


if "REMOTE" in args:
    r = remote(SERVER, PORT)
else: 
    r = process(BINARY)
    gdb.attach(r, """
            #breakpoints
            b* 0x555555555199  
            """)
    #input("wait")


#code

#r.interactive()

