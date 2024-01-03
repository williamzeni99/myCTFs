ORIGINAL_FILE_PATH = "./john"
DUMP_FILES_PATH = [
    ["./dump_1", 0x0804970e], #ok
    ["./dump_2", 0x080492a0], #ok
    ["./dump_3", 0x080492e5], #ok
    ["./dump_4", 0x080496ab], #ok
    ["./dump_5", 0x080495e4], #ok
    ["./dump_6", 0x08049546], #ok
    ["./dump_7", 0x0804951f], #ok
    ["./dump_8", 0x08049329], #ok
    ["./dump_9", 0x08049385], #ok
    ["./dump_10", 0x0804945e] #ok
] 
#with command dump memory NOMEFILESALVARE ADDR_INIZIO ADDR_FINE


#FUNCTION_ADDRRESSES = [0x879879e] #ADDR INIZIO
BINARY_BASE = 0x8048000 #the base of the binary
PATCHED_FILE_PATH = "./john_patched"

def patch_binary(binary, file_path, addr):
    offset = addr - BINARY_BASE
    with open(file_path,"rb") as f: 
        patch = f.read()
    patch_len = len(patch)
    binary = binary[:offset]+patch+binary[offset+patch_len:]
    return binary

with open(ORIGINAL_FILE_PATH, "rb") as f:
    binary = f.read()

for dump in DUMP_FILES_PATH:
    binary = patch_binary(binary, dump[0], dump[1])

with open(PATCHED_FILE_PATH, "wb") as f:
    f.write(binary)

#remember that after this the file is still not executable because of the obfuscation. You have to
#replace the packer and unpacker_function with nope operation if you want to make it executable
    
'''
in this portion of code I just used my snippet to remove the obfuscation on the code
the result was named --> john_patched

then I used ghidra to remove the effect of the obfuscative function and the result 
of the patch was saved in ghidra_patched (the binary I used with z3)
'''