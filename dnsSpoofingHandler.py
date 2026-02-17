import scapy.all as scapy
from attackHandler import AttackHandler
from sqlDataBase import SqliteDatabase
from alert_manager import alert_queue

IP = scapy.IP
UDP = scapy.UDP
DNS = scapy.DNS
DNSQR = scapy.DNSQR
DNSRR = scapy.DNSRR
raw = scapy.raw


class DnsSpoofingHandler(AttackHandler):
    def __init__(self, db: SqliteDatabase):
        super().__init__(db)

    def _force_dissect(self, pkt):
        return IP(raw(pkt))

    def _get_answers(self, dns):
        answers = []
        n = int(dns.ancount or 0)
        for i in range(n):
            rr = dns.an[i]
            if isinstance(rr, DNSRR):
                answers.append(rr)
        return answers

    def detect(self, pkt, email) -> bool:
        if not pkt.haslayer(DNS):
            return False

        pkt2 = self._force_dissect(pkt)
        dns = pkt2[DNS]

        if dns.qr != 1:
            return False

        answers = self._get_answers(dns)

        qname = dns.qd.qname if isinstance(dns.qd, DNSQR) else None

        rule1 = (
            len(answers) == 1 and
            int(answers[0].type) == 1 and
            (qname is None or answers[0].rrname == qname)
        )

        rule2 = not any(int(rr.type) == 5 for rr in answers)
        rule3 = any(int(rr.type) == 1 and int(rr.ttl) in (0, 1, 604800) for rr in answers)

        nscount = int(dns.nscount or 0)
        arcount = int(dns.arcount or 0)
        rule4 = (nscount == 0) and (arcount == 0)
        
        if rule1 and rule2 and rule3 and rule4:
            self.handle(pkt, email)
            print("Attack detected. type: Dns Spoofing.")
            return True
        return False
        #return bool(rule1 and rule2 and rule3 and rule4)

    def handle(self, packet, email):
        ip = packet[IP]
        src_ip = ip.src
        self.db.add_attack(src_ip, "dns_spoofing")
        #sendEmail.send_mail_to_user(email, src_ip, "DNS Spoofing", server)
        alert_queue.put((email, src_ip, "DNS Spoofing"))
