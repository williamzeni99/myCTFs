from pwn import *

# Run with: python example.py

# Environment variables (if needed)
env = {
    # "DEBUG": "1"
}

PLAINTEXT = "Hello world!"
KEY = [11, 2, 9, 3, 0, 5, 10, 7, 1, 6, 4, 8]

# Check length of the plaintext is equal to the length of the key
assert len(PLAINTEXT) == len(KEY)
# Run the program
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
    print(cycles)
# Received cyphertext
c.recvuntil(b"Ciphertext: ")
ciphertext = c.recvuntil(b"\n").split(b"\n")[0]
print("Ciphertext:", ciphertext.decode())
# Close program
c.close()