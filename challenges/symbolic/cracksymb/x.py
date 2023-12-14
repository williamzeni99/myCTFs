import angr
import claripy 
from pwn import *
from sys import *

BINARY = "./cracksymb"

TARGET = 0x403370

chars =[claripy.BVS(f'check_{i}', size=8) for i in range(0x17)]
flag = claripy.Concat(*chars)

proj = angr.Project(BINARY)
entry_state = proj.factory.entry_state(stdin=flag, add_options={angr.options.LAZY_SOLVES})

for char in chars:
    entry_state.solver.add(char>=0x20)
    entry_state.solver.add(char<=0x7e)

i=0
for x in "flag{":
    entry_state.solver.add(chars[i]== ord(x))
    i+=1
entry_state.solver.add(chars[0x16]== ord('}'))


simgr = proj.factory.simulation_manager(entry_state)

simgr.explore(find=TARGET)

if simgr.found:
    found = simgr.found[0]
        
    # Ottieni la rappresentazione byte della flag
    flag_ = found.solver.eval(flag, cast_to=bytes)
    print("[!] FLAG: ",flag_)
    
else:
    print("Flag non trovata")

'''
This challenge is similar to prodkey with only one difference. The number of if-else
condition are a lot more. So if you simply set the simulation as always it will take 
forever to compute everything. In order to reduce the number of steps in the simulation 
you have to properly set the first bytes of the flag to be "flag{" and the last one to be "}".
But this is not enough. After a long and painfull serch looking at the angr documentation
in the section "Simulation Manager" I discovered the option 'LAZY_SOLVES'. Basically, 
at each step the simulation manager tries to check multiple conditions in order to cut the step.
Doing that is very painfull in a program like this one. With LAZY_SOLVES the doability check
is done just if it is necessary (look at the documentation). With this option is a matter of 
seconds resolve the challenge. 
'''

