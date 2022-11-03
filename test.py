from scapy.all import *
from scapy.all import IP, Ether, ARP, ICMP


IP_MAC_responses = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.5.1.0/24"), timeout=2)[0]
a = IP_MAC_responses[0][1].hwsrc
print(a)