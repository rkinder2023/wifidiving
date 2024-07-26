# anonymizer scripts
Files related to the WiFi Diving article covering how to anonymize a sniffer trace using Scapy.

The following files are available for your learning pleasure!

 - read_packets.py: Very simple script to read in all packets from a sniffer trace.
 - replace_mac_addresses.py: Replace MAC addresses in packets based on a dictionary of MAC mappings.
 - find_eapol_key.py: Find the EAPOL key packets in a trace and print them out.
 - find_first_eapol.py: Find the first EAPOL key packet in a trace, for interactive manipulation.
 - eapol_key_replace.py: Obfuscate the EAPOL key packet fields which could be used for offline dictionary attacks.
 - obfuscate_trace.py: Complete program to replace MAC addresses and to manipulate EAPOL key packet fields, to do a partial anonymization of a sniffer trace.
