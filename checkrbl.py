#!/usr/bin/env python

import urllib
import urllib2
import re
import sys
import subprocess as sp
import signal
import struct
import socket
import array
import fcntl
import optparse

INSTALLDIR = '/root/cpanelsec'

parser = optparse.OptionParser(usage="check_rbl [options] [IP-Address]")
parser.add_option('-a', '--all', help="check all interface IPs", default=False, 
                    dest='all_ips', action='store_true')

(opts, args) = parser.parse_args()


regex = re.compile("Email.Reputation.*?colspan.*?class=.(\w+)", re.MULTILINE|re.DOTALL)
postdata = [('tos_accepted', 'Yes, I Agree')]
postdata = urllib.urlencode(postdata)


# get all interface IPs
# http://code.activestate.com/recipes/439093-get-names-of-all-up-network-interfaces-linux-only/
def getIPs():
    struct_size = 40
    if 8*struct.calcsize('P') == 32:
        struct_size -= 8
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8

    while True:
        bytes = max_possible * struct_size
        names = array.array('B', '\0' * bytes)
        outbytes = struct.unpack('iL', fcntl.ioctl(s.fileno(), 0x8912, 
            struct.pack('iL', bytes, names.buffer_info()[0])))[0]
        if outbytes == bytes:
            max_possible *= 2
        else:
            break

    namestr = names.tostring()

    IPtuples = [(namestr[i:i+16].split('\0',1)[0],socket.inet_ntoa(
                    namestr[i+20:i+24])) for i in range(0, outbytes, struct_size)]
    
    ips = [ x[1] for x in IPtuples if not '127.0.0' in x[1] and not '192.168.' in x[1] ]
   
    return ips


def signal_handler(signal, frame):
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def red(text):
    return '\033[31m' + text + '\033[0m'

def green(text):
    return '\033[32m' + text + '\033[0m'

def valid_IP(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except socket.error:
        return False

    return True


RBLs = open(INSTALLDIR + "/rbls", 'r').read().rstrip().split('\n')
RBLs = [ x.split(';') for x in RBLs]
reverseIP = lambda x: '.'.join(x.split('.')[::-1])

ipList = getIPs()
if not opts.all_ips:
    ipList = [ipList[0]]

if len(args) == 1 and valid_IP(args[0]):
    ipList = [args[0]]


for ip in ipList:
    rev = reverseIP(ip)
    for rbl in RBLs:
        p = sp.Popen("dig +short " + rev + "." + rbl[1], stdout=sp.PIPE,shell=True)
        res = p.stdout.read()
        p.stdout.close()
        if res:
            print ip + red(" LISTED ") + "in " + rbl[0] + " - " + rbl[2]
        else:
            print ip + " not listed in " + rbl[0]

    print ''
