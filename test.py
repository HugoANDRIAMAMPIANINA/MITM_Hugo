from scapy.all import *
from scapy.all import IP, Ether, ARP, ICMP

for i in range(1,255):
    print(i)

ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.5.1.0/24"), timeout=2)
responses = ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
print(responses)

ans2, unans2 = sr(IP(dst="192.168.1.0/24")/ICMP(), timeout=3)
responses = ans.summary(lambda s,r: r.sprintf("%IP.src%") )
print(responses)