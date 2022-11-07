from scapy.all import *
from scapy.all import IP, Ether, ARP, ICMP

frame = Ether(dst="ff:ff:ff:ff:ff:ff")

arp_packet = frame/ARP(pdst="10.5.1.0/24")

IP_MAC_responses, unans = srp(arp_packet, timeout=2)


print(IP_MAC_responses.summary)
#i = IP_MAC_responses.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%"))
print(unans)

#victim_IP = djjdjddjd

#spoof_arp_packet = frame/ARP(pdst=victim_IP, op=2, psrc=victim_IP)
