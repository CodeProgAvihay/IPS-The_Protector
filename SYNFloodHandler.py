import time
from attackHandler import AttackHandler
import scapy.all as scapy
from alert_manager import alert_queue

IP = scapy.IP
TCP = scapy.TCP

class SynFloodHandler(AttackHandler):
    def __init__(self, _db, time_window=5, syn_threshold=40, min_ratio=0.2):
        super().__init__(_db)
        self.time_window = time_window
        self.syn_threshold = syn_threshold  # כמה SYN נחשב חריג
        self.min_ratio = min_ratio  # ACK/SYN מינימלי
        self.stats = {}

    def detect(self, packet, email):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return False

        ip = packet[IP]
        tcp = packet[TCP]
        src = ip.src
        now = time.time()

        flags = tcp.flags

        if src not in self.stats:
            self.stats[src] = {
                "syn": 0,
                "ack": 0,
                "start": now
            }

        entry = self.stats[src]

        if now - entry["start"] > self.time_window:
            entry["syn"] = 0
            entry["ack"] = 0
            entry["start"] = now

        if flags & 0x02 and not flags & 0x10:
            entry["syn"] += 1

        if flags & 0x10:
            entry["ack"] += 1

        if entry["syn"] < self.syn_threshold:
            return False

        ratio = entry["ack"] / entry["syn"]

        if ratio < self.min_ratio:
            self.handle(packet, email)
            print("Attack detected. type: SYN Flood.")
            del self.stats[src]
            return True

        return False

    def handle(self, packet, email):
        self.db.add_attack(packet[IP].src, "syn_flood")
        #sendEmail.send_mail_to_user(email, packet[IP].src, "SYN Flood", server)
        alert_queue.put((email, packet[IP].src, "SYN Flood"))
