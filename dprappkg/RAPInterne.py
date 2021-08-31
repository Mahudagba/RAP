try:
    from os import system
    from sys import exit
    from scapy.all import *
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
except:
    system("clear")
    print(e)


def rap_ether():
    try:
        print('\033[34m', "Notice: At the end sending packet press CTRL+C to see results.", '\033[0m', sep='')
        conf.checkIPaddr = False
        fam, hw = get_if_raw_hwaddr(conf.iface)
        dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68,
                                                                                                        dport=67) / BOOTP(
            chaddr=hw) / DHCP(options=[("message-type", "discover"), "end"])
        ans, unans = srp(dhcp_discover, multi=True)  # Press CTRL-C after several seconds
        for p in ans:
            print(p[1][Ether].src, p[1][IP].src)
    except PermissionError as pe:
        system("clear")
        print('\033[31m', "Notice: You must have root permission.", '\033[0m', sep='')
        exit(0)
