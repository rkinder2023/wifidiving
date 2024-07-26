# This script will read in a file and modify EAPOL packets by inserting
# random data into the key_nonce, key_iv, key_rsc, key_id and key_mic fields.
# Additional code is needed to write this back to a pcap file.
from scapy.all import *

filename = "initial-connection-plus-ping.pcap"
pcap_reader = PcapReader(filename)

def obfuscate_eapol_key(eapol_key):
    # The attributes we want to replace
    attributes = ["key_nonce", "key_iv", "key_rsc", "key_id", "key_mic"]

    for attribute in attributes:
        # Replace each attribute with some random values - use os.urandom
        print(f"Attribute {attribute}: {getattr(eapol_key, attribute)}")
        setattr(eapol_key, attribute, os.urandom(len(getattr(eapol_key, attribute))))
        print(f"New attribute {attribute}: {getattr(eapol_key,  attribute)}")

# Main loop
for pkt in pcap_reader:
    if pkt.haslayer(EAPOL_KEY):
        obfuscate_eapol_key(pkt)
