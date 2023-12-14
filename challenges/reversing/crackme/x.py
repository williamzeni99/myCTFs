def xor_bytes(bytes1, bytes2):
    return bytes(x ^ y for x, y in zip(bytes1, bytes2))

key2 = b'\x7f\xef\xe8\xb5\x15\x73\xb4\x6a\xa7\x7d\x48\xdd\xea\x6a\x9d\xaa\x82\xfa\x6e\xe4\xf6\x23\x9b\xd9\x78\xab\x1b\x9b\x16\x96\x9c\x2e\x6f\xb2\xc7\x0c\x17\x00\x00'
key1 = b'\x19\x83\x89\xd2\x6e\x1f\x84\x1c\x94\x11\x31\x82\xde\x04\xe9\x9b\xf0\xc9\x18\xbb\x82\x51\xaa\xba\x13\x9e\x44\xec\x49\xe5\xad\x49\x01\x86\xab\x39\x6a\x00\x00'

final_key = xor_bytes(key1, key2); 
print(final_key)

'''
This challenge on reversing was a real pain in the ass at the beginning. Basically, there is an instruction called
INT3 in the binary that prevents ghidra to correctly decompile the code. In addiction there is a function called
"catch_function" that is obviously the one doing the "real code". I'm sure I did not fully understand the flow of 
the code because during the debugging it never runs the function, even if I'm sure it does. So, I forced the binary
jumping into the function by patching INT3 function using ghidra (look at the result binary crackme2). 
After the jump I was able to look at the flow of the function (also explained by chatgpt) and I was able to understand
which registers contained the bytes of the keys. The input was xored with a key1 and later compared with a key2. 
So, what I have done was to find the key2 and key1 and xor them in order to have my flag. 


'''