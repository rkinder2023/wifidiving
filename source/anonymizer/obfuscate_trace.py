# This script is a combination of the different pieces and can do a simple
# obfuscation of a sniffer trace file by replacing the MAC addresses of certain
# devices, and by randomising the data within the EAPOL-KEY packets.
# This provides some level of anonymity, but further changes would be necessary
# to ensure all user identifiable data is purged/altered.

from scapy.all import *

filename = "initial-connection-plus-ping.pcap"
pcap_reader = PcapReader(filename)

# Take a packet and a dictionary of MAC addresses to replace, and do
# the necessary for all of the addresses found in the packet.
# If any of the addresses are changed, invalidate the FCS so that
# Scapy will regenerate the FCS when writing back to a pcap file.
def substitute_mac(pkt, _mac_map_list):
    # The fields 'addr1' -> 'addr4' are the internal Scapy addresses
    for addr_id in ["addr1", "addr2", "addr3", "addr4"]:
        # See if this pkt has the given MAC address identifier
        if hasattr(pkt, addr_id):
            # The actual MAC address for the field addr_in
            addr = getattr(pkt, addr_id)
            if addr in _mac_map_list:
                # Hit - this 'addr_id' field is one of the map addrs
                print(f"Replacing address {addr} with {_mac_map_list[addr]}")
                # Replace it with the mapped address
                setattr(pkt, addr_id, _mac_map_list[addr])
                pkt.fcs = None


# Take an EAPOL-KEY packet and obfuscate the fields which could be used
# for offline dictionary attacks (nonce, iv, rsc, id and mic fields).
def obfuscate_eapol_key(eapol_key):
    # The attributes we want to replace
    attributes = ["key_nonce", "key_iv", "key_rsc", "key_id", "key_mic"]

    for attribute in attributes:
        # Replace each attribute with some random values
        print(f"Attribute {attribute}: {getattr(eapol_key, attribute)}")
        setattr(eapol_key, attribute, os.urandom(len(getattr(eapol_key, attribute))))
        print(f"New attribute {attribute}: {getattr(eapol_key,  attribute)}")
        pkt.fcs = None

# Save all the packets to write them out. Warning: this won't work well for large traces!
all_pkts = []

# Main loop, do the necessary changes to all packets as necessary.
for pkt in pcap_reader:
    # Substitute MAC address dictionary
    mac_map_list = {"00:26:86:f0:7d:67": "02:2F:3A:4B:5C:6D",
                    "2c:cf:67:01:0b:a3": "02:01:02:03:04:5F"}

    # Update the MAC address if necessary
    substitute_mac(pkt, mac_map_list)

    # Update and obfuscate the EAPOL-KEY frame fields
    if pkt.haslayer(EAPOL_KEY):
        obfuscate_eapol_key(pkt)

    # Save the packet regardless of update
    all_pkts.append(pkt)

# Write the packets back out to a pcap file
wrpcap(f"obfuscated_{filename}", all_pkts)
