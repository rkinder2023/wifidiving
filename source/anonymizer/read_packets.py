# This script reads in and prints all the packets in a trace to the output.
from scapy.all import *

filename = "initial-connection-plus-ping.pcap"
pcap_reader = PcapReader(filename)

for pkt in pcap_reader:
    print(pkt)

