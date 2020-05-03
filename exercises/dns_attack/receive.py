#!/usr/bin/env python

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

def handle_pkt(pkt):
	if pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt.getlayer(DNS).qr==0:
	    print "got a packet"
	    domainname = pkt[DNS].qd.qname
	    iface = get_if()
	    if domainname in dic:
	    	respkt = \
	    	 Ether(src=get_if_hwaddr(iface), dst=pkt[Ether].src) /\
	    	 IP(dst=pkt[IP].src, tos=1) /\
	    	 UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) /\
	    	 DNS(id=pkt[DNS].id, qr=1, aa=1, ancount=1, qd=pkt[DNS].qd, an=DNSRR(rrname=domainname, rdata=dic[domainname]))
    		respkt.show2()
    		sendp(respkt, iface=iface)
    	sys.stdout.flush()


def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()