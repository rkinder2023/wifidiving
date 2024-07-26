# This script will replace MAC addresses in the addr1 -> addr4 fields
# based on the mac_map_list dictionary
from scapy.all import *

pcap_reader = PcapReader("initial-connection-plus-ping.pcap")

def substitute_mac(pkt, _mac_map_list):
    # The fields 'addr1' -> 'addr4' are the internal Scapy addresses
    for addr_id in ["addr1", "addr2", "addr3", "addr4"]:
        # See if this pkt has the given MAC address identifier
        if hasattr(pkt, addr_id):
            # The actual MAC address for the field addr_in
            addr = getattr(pkt, addr_id)
            if addr in _mac_map_list:
                # Hit - this 'addr_id' field is one of the map addrs
                # Replace it with the mapped address
                setattr(pkt, addr_id, _mac_map_list[addr])

for pkt in pcap_reader:
    # Modify this as appropriate
    mac_map_list = {"00:26:86:f0:7d:67": "02:2F:3A:4B:5C:6D",
                    "2c:cf:67:01:0b:a3": "02:01:02:03:04:5F"}
    substitute_mac(pkt, mac_map_list)
