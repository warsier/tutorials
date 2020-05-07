#!/usr/bin/env python

#!/usr/bin/env python

import argparse
import socket

from scapy.all import *

from time import sleep

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
    # print "got a packet"
    pkt.show2()

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--des", help="IP address of the destination", type=str)
    parser.add_argument("--dur", help="packet count", type=str)
    args = parser.parse_args()

    if args.des and args.dur:
        addr = socket.gethostbyname(args.des)
        iface = get_if()

        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, tos=1) / UDP(dport=53, sport=1234) / DNS(rd=1, qd=DNSQR(qname='a.com'))
        print pkt
        pkt.show2()
        try:
            for i in range(int(args.dur)):
                sendp(pkt, iface=iface, verbose=0)
                # sniff(iface=iface, prn=lambda x: handle_pkt(x))
            print "total packet sent =", int(args.dur)
        except KeyboardInterrupt:
            raise


if __name__ == '__main__':
    main()