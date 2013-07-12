#!/usr/bin/env python

import subprocess as sp
from time import sleep
import signal
import sys


def signal_handler(signal, frame):
	sys.exit(0)

COUNT = 0
ADDR = 1


def getIPs():
	p = sp.Popen("netstat -plan | grep :80 | awk '{print $5}' | cut -d : -f1 | sort -nk1 | uniq -c | sort -rnk1", shell=True, stdout=sp.PIPE)
	output = p.stdout.readlines()
	return [ x.split() for x in output ]


def isDropped(ip):
	p = sp.Popen("csf -g " + ip[ADDR] + " | grep DROP", shell=True, stdout=sp.PIPE)
	if p.stdout.read():
		return True
	
	return False


def deny(ip, sec):
	sp.Popen("csf -td " + ip[ADDR] + " " + str(sec), shell=True, stdout=sp.PIPE)
	print ip[ADDR] + " has " + ip[COUNT] + " connections....dropping for " + str(sec/60) + " minutes!"


if __name__ == "__main__":

	signal.signal(signal.SIGINT, signal_handler)

	while True:
			
		for ip in getIPs():
			if isDropped(ip):
				continue

			cons = int(ip[COUNT])
			
			# getIPs sorts results based on number of connections, so if we hit an
			# IP with less than 30 connections, all the rest will also be < 30
			if cons < 30:
				break
					
			elif cons >= 30 and cons < 60:
				deny(ip, 300)
			
			elif cons >= 60 and cons < 90:
				deny(ip, 600)

			elif cons >= 90:
				deny(ip, 1800)

		sleep(10)
