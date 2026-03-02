import time
import math
from collections import defaultdict, deque
from scapy.all import DNS, DNSQR, IP, UDP
from attackHandler import AttackHandler
from alert_manager import alert_queue, event_queue
import pop_up_alert

class DNSTunnelHandler(AttackHandler):
    def __init__(self, _db):
        super().__init__(_db)
        self.history = defaultdict(lambda: deque())
        self.window = 10
        self.max_queries = 25
        self.min_label_len = 20
        self.entropy_threshold = 3.5

    def detect(self, packet, email):
        if not packet.haslayer(IP) or not packet.haslayer(UDP) or not packet.haslayer(DNS):
            return False
        
        dns = packet[DNS]
        if dns.qr != 0 or dns.opcode != 0:
            return False

        qname = dns[DNSQR].qname.decode(errors="ignore").rstrip(".")
        src_ip = packet[IP].src
        now = time.time()
        self.cleanup(src_ip, now)

        score = 0
        if self.is_long_label(qname):
            score += 1
        if self.high_entropy(qname):
            score += 1
        if self.high_frequency(src_ip, now):
            score += 1
        if self.random_pattern(qname):
            score += 1

        if score >= 3:
            self.handle(packet, email)
            return True

        return False


    def cleanup(self, ip, now):
        q = self.history[ip]
        while q and now - q[0] > self.window:
            q.popleft()


    def high_frequency(self, ip, now):
        q = self.history[ip]
        q.append(now)
        return len(q) > self.max_queries


    def is_long_label(self, domain):
        labels = domain.split(".")
        return any(len(label) >= self.min_label_len for label in labels)


    def high_entropy(self, data):
        if not data:
            return False
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy > self.entropy_threshold


    def random_pattern(self, domain):
        letters = sum(c.isalpha() for c in domain)
        digits = sum(c.isdigit() for c in domain)

        if letters == 0:
            return False

        ratio = digits / letters
        return ratio > 0.5
    
    def handle(self, packet, email):
        ip = packet[IP]
        src_ip = ip.src
        self.db.add_attack(src_ip, "dns_tunneling")
        alert_queue.put((email, src_ip, "Dns Tunnle"))
        event_queue.put({
            "type": "alert",
            "time": time.strftime("%H:%M:%S"),
            "attack": "DNS Tunneling",
            "ip": src_ip,
            "severity": "HIGH"
        })
        pop_up_alert.popup_alert(f"ATTACK DETECTED!!!\n\nIP: {src_ip}\n\nType: DNS Tunneling.")
