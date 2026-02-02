from attackHandler import AttackHandler
import scapy.all as scapy
import subprocess
import ipaddress
from typing import Optional

ARP = scapy.ARP
Ether = scapy.Ether
srp = scapy.srp
IP = scapy.IP

class arpSpoofingHandler(AttackHandler):
    def __init__(self):
        self.arp_table_verified = {}
        subnet = self.get_local_subnet()
        print(f"[INFO] Detected subnet: {subnet}")

        arp_table = self.build_arp_table(subnet)
        for ip, mac in arp_table.items():
            print(f"{ip} -> {mac}")

    def get_rp_table_verified(self):
        return self.arp_table_verified

    def _get_default_iface(self) -> str:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True).strip()
        parts = out.split()
        if "dev" not in parts:
            raise RuntimeError("Could not find default interface (no 'dev' in ip route output)")
        return parts[parts.index("dev") + 1]

    def get_local_subnet(self, iface: Optional[str] = None) -> str:
        if iface is None:
            iface = self._get_default_iface()

        out = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show", "dev", iface],
            text=True
        ).strip()

        cidr = None
        for token in out.split():
            if "/" in token and token.count(".") == 3:
                cidr = token
                break

        if not cidr:
            raise RuntimeError("Could not detect local subnet from: " + out)

        network = ipaddress.IPv4Network(cidr, strict=False)
        return str(network)

    def build_arp_table(self, subnet: str, timeout: int = 2) -> dict:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(packet, timeout=timeout, verbose=0)

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc.lower()
            self.arp_table_verified[ip] = mac

        return self.arp_table_verified

    def detect(self, pkt) -> bool:

        if not pkt or not pkt.haslayer(ARP):
            return False

        arp = pkt[ARP]

        is_reply = arp.op == 2
        is_gratuitous = arp.psrc == arp.pdst
        if not (is_reply or is_gratuitous):
            return False

        ip = arp.psrc
        mac = arp.hwsrc.lower()

        if ip in self.arp_table_verified:
            trusted_mac = self.arp_table_verified[ip].lower()
            if mac != trusted_mac:
                return True
            else:
                return False

        else:
            return False


    def handle(self, packet):
        ip = packet[IP]
        src_ip = ip.src
        self.db.add_attack(src_ip)



