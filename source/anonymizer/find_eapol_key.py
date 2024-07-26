# This script will read in and print any EAPOL-KEY packets to the output along
# with their packet number within the trace.
from scapy.all import *

count = 1
pcap_reader = PcapReader("initial-connection-plus-ping.pcap")
eapol_pkts = []

for pkt in pcap_reader:
    # haslayer can find all layers of the packet and be used to filter out
    # what the application needs.
    if pkt.haslayer(EAPOL_KEY):
        print(f"Packet {count} is an EAPOL-KEY packet:")
        print(pkt)
        eapol_pkts.append(pkt)
    count += 1
