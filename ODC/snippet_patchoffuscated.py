ORIGINAL_FILE_PATH = "./chellenge_binary"
DUMP_FILES_PATH = [
    ["./dump_from_gdb", 0x709500] #addr inizio
] 
#with command dump memory NOMEFILESALVARE ADDR_INIZIO ADDR_FINE


#FUNCTION_ADDRRESSES = [0x879879e] #ADDR INIZIO
BINARY_BASE = 0x354957 #the base of the binary
PATCHED_FILE_PATH = "./where_to_save_path"

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