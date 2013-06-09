#!/usr/bin/env python

import subprocess as sp

def red(text):
    return '\033[91m' + text + '\033[0m'

f = open("rbls", "r")
RBLs = f.read().rstrip().split('\n')
f.close()

RBLs = [ x.split(';') for x in RBLs]
reverseIP = lambda x: '.'.join(x.split('.')[::-1])

# get list of IPs by parsing ifconfig
cmd = "ifconfig | grep -v 127.0.0.1 | grep 'inet addr' | cut -d':' -f2 | awk -F'Bcast' '{print $1}'"
p = sp.Popen(cmd, stdout=sp.PIPE,shell=True)
IPs = p.stdout.read().split('\n')
IPs.pop() # last item is empty
IPs = [ x.strip() for x in IPs ]

# list of rbls which the ip IS listed on
blacklists = []

for ip in IPs:
    rev = reverseIP(ip)
    for rbl in RBLs:
        p = sp.Popen("dig +short " + rev + "." + rbl[1], stdout=sp.PIPE,shell=True)
        res = p.stdout.read()
        if res:
            print ip + red(" LISTED ") + "in " + rbl[0]
            blacklists.append(ip + " listed on " + rbl[0] + " ( " + rbl[2] + " )")
        else:
            print ip + " not listed in " + rbl[0]
