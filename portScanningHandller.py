from attackHandler import AttackHandler
from scapy.all import IP, TCP
import time


class PortScanningHandler(AttackHandler):
    def __init__(self, _db, time_window = 3, ports_checked = 10):
        super().__init__(_db)
        self.time_window = time_window
        self.port_checked = ports_checked
        self.scans = {}

    def detect(self, packet):
        print("Trying to analyze the packet.")
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return False

        ip = packet[IP]
        tcp = packet[TCP]

        src_ip = ip.src
        dst_port = tcp.dport
        flags = tcp.flags
        now = time.time()

        scan_type = self.check_scan_type(flags)
        if scan_type is None:
            return False

        if src_ip not in self.scans:
            self.scans[src_ip] = {
                "ports": set(),
                "timestamps": [],
                "types": set()
            }
        
        entry = self.scans[src_ip]
        entry["ports"].add(dst_port)
        entry["timestamps"].append(now)
        entry["types"].add(scan_type)

        self.cleanup_old(src_ip, now)

        if len(entry["ports"]) >= self.port_checked:
            self.handle(packet)
            print("Attack detected. type:", scan_type)
            self.reset(src_ip)
            return True
        
        return False

    def check_scan_type(self, flags):
        if flags == 0x02:
            return "SYN Scan"
        if flags == 0x01:
            return "FIN Scan"
        if flags == 0x00:
            return "NULL Scan"
        if flags == 0x29:
            return "XMAS Scan"
        return None
    
    def cleanup_old(self, src_ip, now):
        entry = self.scans[src_ip]
        new_times = []
        for t in entry["timestamps"]:
            if now - t <= self.time_window:
                new_times.append(t)
        entry["timestamps"] = new_times
        if not entry["timestamps"]:
            self.reset(src_ip)

    def reset(self, src_ip):
        del self.scans[src_ip]

    def handle(self, packet):
        ip = packet[IP]
        src_ip = ip.src
        self.db.add_attack(src_ip, "port_scanning")