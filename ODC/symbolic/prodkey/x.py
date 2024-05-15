import angr
import claripy
from pwn import *
from sys import *

SERVER = "bin.training.offdef.it"
PORT = "2021"
BINARY = "./prodkey"


TARGET = 0x400deb

chars =[claripy.BVS(f'check_{i}', size=8) for i in range(32)]
flag = claripy.Concat(*chars)

proj = angr.Project(BINARY)
entry_state = proj.factory.entry_state(stdin=flag)

for char in chars:
    entry_state.solver.add(char>=0x20)
    entry_state.solver.add(char<=0x7e)

simgr = proj.factory.simulation_manager(entry_state)
simgr.explore(find=TARGET)

if simgr.found:
    if "--remote" in sys.argv:
        r = remote(SERVER, PORT)
    else:
        r = process(BINARY)
    found = simgr.found[0]
        
    # Ottieni la rappresentazione byte della flag
    prodkey = found.solver.eval(flag, cast_to=bytes)
    print("[!] calculated product_key:", prodkey)
    r.recv()
    sleep(0.1)
    r.sendline(prodkey)
    flag = r.recv()
    print("[!] FLAG: ",flag)
    
else:
    print("Flag non trovata")


'''
Challenge made by the professor. Basically this code has no vulnerabilities, 
so the only way to exploit it is to reach line 0x400deb where the flag is open.
To reach that line, you should study all the checks and do reverse_engineering. 
With angr we can do it automatically by setting the right constraint. Basically
we set the flag as an array of bytes (each byte is a 8 bit array variable to be evaluated)
and we set the bytes to be printable. 

'''