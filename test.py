from scapy.all import *
from scapy.all import IP, Ether, ARP, ICMP

ans1, unans1 = sr(IP(dst="10.5.1.1",proto=(0,255))/"SCAPY",retry=2)


ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="10.5.1.0/24"), timeout=2)
IP_MAC_responses = ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
print(IP_MAC_responses)
