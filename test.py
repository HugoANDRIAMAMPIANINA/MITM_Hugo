from scapy.all import *
from scapy.all import IP, Ether, ARP, ICMP

frame = Ether(dst="ff:ff:ff:ff:ff:ff")

arp_packet = frame/ARP(pdst="10.5.1.0/24")

IP_MAC_responses, unans = srp(arp_packet, timeout=2)

MAC_on_network = []
IP_on_network = []

for i in range(len(IP_MAC_responses)):
    MAC_on_network.append(IP_MAC_responses[i][1].hwsrc)
    IP_on_network.append(IP_MAC_responses[i][1].psrc)

print(MAC_on_network, IP_on_network)

#victim_IP = djjdjddjd

#spoof_arp_packet = frame/ARP(pdst=victim_IP, op=2, psrc=victim_IP)
