# This script will run through a trace and find the first EAPOL-KEY
# packet.
from scapy.all import *

filename = "initial-connection-plus-ping.pcap"
pcap_reader = PcapReader(filename)

for pkt in pcap_reader:
    if pkt.haslayer(EAPOL_KEY):
        break

print(pkt)
