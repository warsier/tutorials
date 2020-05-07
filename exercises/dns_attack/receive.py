#!/usr/bin/env python

import argparse
import sys

from scapy.all import *



dic = {
    "a.com.":"1.2.3.4",
    "b.com.":"2.3.4.5",
    "c.com.":"4.5.6.7"
}

def get_if():
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

resp_flag = False
pkt_counter = 0

def handle_pkt(pkt):
    global resp_flag
    global pkt_counter
    if pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt.getlayer(DNS).qr==0:
        # print "got a packet"
        pkt.show2()
        domainname = pkt[DNS].qd.qname
        iface = get_if()
        if domainname in dic:
            respkt = \
             Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src) /\
             IP(dst=pkt[IP].src, tos=1) /\
             UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /\
             DNS(id=pkt[DNS].id, qr=1, aa=1, ancount=1, qd=pkt[DNS].qd, an=DNSRR(rrname=domainname, rdata=dic[domainname]))
            if not resp_flag:
                respkt.show2()
                resp_flag = True
            pkt_counter += 1
            sendp(respkt, iface=iface, verbose=0)
        sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser()
    args = parser.parse_args()


    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    try:
        sniff(iface=iface, prn=lambda x: handle_pkt(x))
    except KeyboardInterrupt:
        raise
    print "total packet received =", pkt_counter

if __name__ == '__main__':
    main()