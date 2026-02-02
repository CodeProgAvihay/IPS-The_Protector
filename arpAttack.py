import random
from arpSpoofingHandler import arpSpoofingHandler
import scapy.all as scapy
ARP = scapy.ARP
Ether = scapy.Ether


def arp_attack():
    arp_test = arpSpoofingHandler()
    if arp_test.get_rp_table_verified():
        ip = random.choice(list(arp_test.get_rp_table_verified().keys()))
    else:
        print("Table is empty")

    # used ff:ff:ff:ff:ff:ff as mac address because no device can have this address
    gratuitous_arp = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src="ff:ff:ff:ff:ff:ff") /
            ARP(op=2, psrc=ip, pdst=ip, hwsrc="ff:ff:ff:ff:ff:ff")
    )
    gratuitous_arp.show()
    print(arp_test.detect(gratuitous_arp))
