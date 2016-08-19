#!/usr/bin/env python2
#encoding: UTF-8

import os
import sys
import logging
import yaml
from scapy.all import srp,Ether,ARP,conf

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

handler = logging.FileHandler('/var/log/Scripts/ARPJanitor')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)


if len(sys.argv) != 2:
    print "Usage: ARPJanitor <net>\n  eg: ARPJanitor 192.168.1.0/24"
    sys.exit(1)



machines = {}
current = {}

def event_triggerer (event, mac, ip):
    if mac in yml.keys():
        if yml[mac][event]['shell']!='':
            if isinstance ( yml[mac][event]['shell'], list):
                for command in yml[mac][event]['shell']:
                    logger.info("Executing: %s ([%s] %s)", command, mac, event)
                    os.popen(command)
            else:                   
                logger.info("Executing: %s ([%s] %s)", yml[mac][event]['shell'], mac, event)
                os.popen(yml[mac][event]['shell'])
        else:
            logger.info('No actions defined for %s (%s)', (mac, event))
          
    else:
        logger.info('No configuration defined for %s', mac)


def machine_joins (mac, ip):
    current[mac]=ip

    if mac not in machines:
	string="Joined: %s (%s)" % (mac, ip)
	logger.info(string)
	machines[mac]=ip
	event_triggerer('joins', mac, ip)


def machine_leaves ():
    for x in machines.keys():
	if x not in current:
	    string="Leaves: %s (%s)" % (x, machines[x])
#	    print "Leaves: %s (%s)" % (x, machines[x])
	    logger.info(string)
	    event_triggerer('leaves', x, machines[x])
	    del machines[x]

    

conf.verb=0
logger.info("Initializing (loading YML)")

with open(os.path.dirname(os.path.abspath(__file__))+"/ARPJanitor.yml", 'r') as stream:
    try:
        yml=yaml.load(stream)
    except yaml.YAMLError as exc:
        print(exc)


try:
    while True:
	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1]), timeout=2)
        for snd,rcv in ans:
	    machine_joins (rcv.sprintf(r"%Ether.src%"), rcv.sprintf(r"%ARP.psrc%"))
	machine_leaves ()
	current = {}
except KeyboardInterrupt:
    sys.exit("Ctrl-C detected!")


