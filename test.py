from scapy.all import *
from scapy.all import IP, Ether, ARP, ICMP


ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.5.1.0/24"), timeout=2)
IP_MAC_responses = ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
print(IP_MAC_responses[0][0].hwsrc)
print(IP_MAC_responses[0][1].hwsrc)
print(IP_MAC_responses[1][0].hwsrc)
