from pwn import *
from sys import *

SERVER = "bin.chall.necst.it"
PORT = 22
BINARY = "mission0"
REMOTE_BINARY = "/home/m226002/"+BINARY+"/"+BINARY
PASSWORD = "unixporn"
USER  = "m226002"


if "--remote" in sys.argv:
    s = ssh(user=USER, host=SERVER, port=PORT, password=PASSWORD)
    r = s.process(REMOTE_BINARY)
else:
    r = process(BINARY)

if "--debug" in sys.argv:
     
    gdb.attach(r, """
        #breakpoints
        b* 0x804927d
        c
        """)
    input("wait")

#code 

