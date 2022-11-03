from scapy.all import *
from scapy.all import IP, Ether, ARP 

for i in range(1,255):
    print(i)

ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.5.1.0/24"), timeout=2)
responses = ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
print(responses)
