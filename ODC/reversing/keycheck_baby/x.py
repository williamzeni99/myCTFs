from pwn import *

def xor_bytes(bytes1, bytes2):
    return bytes(x ^ y for x, y in zip(bytes1, bytes2))

magic1 = b'\xeb\x51\xb0\x13\x85\xb9\x1c\x87\xb8\x26\x8d\x07'
magic0 = b'\x1b\x51\x17\x2a\x1e\x4e\x3d\x10\x17\x46\x49\x14\x3d'

firstxor = b'babuzzbabuzzb'

out = xor_bytes(firstxor, magic0)

new_magic1 = b'\xbb'+magic1

result = b'flag{'+ out
for i in range(12):
    y = new_magic1[i+1] - new_magic1[i]
    y = y%256
    my_bytes = y.to_bytes(1, byteorder='big')
    result += my_bytes
    
result+=b'}'
print(result)


'''
This challenge was "simple". You just have to look into the code and understand what it does. Once done,
you can easily run a python code to generate the key. No special skills for this challenge. 
'''