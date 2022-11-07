from scapy.all import *
from scapy.all import IP, Ether, ARP, ICMP


ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.5.1.0/24"), timeout=2)
print(ans)
