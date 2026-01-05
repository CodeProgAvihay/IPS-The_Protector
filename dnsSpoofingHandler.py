import scapy.all as scapy
from attackHandler import AttackHandler
from sqlDataBase import SqliteDatabase

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

    def detect(self, pkt) -> bool:
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


        return bool(rule1 and rule2 and rule3 and rule4)

    def handle(self, packet):
        ip = packet[IP]
        src_ip = ip.src
        self.db.add_address(src_ip)

def build_legit_dns_response():
    return (
        IP(src="8.8.8.8", dst="192.168.1.5") /
        UDP(sport=53, dport=49532) /
        DNS(
            id=0x1234,
            qr=1,
            aa=1,
            rd=1,
            qd=DNSQR(qname="www.example.com", qtype="A"),
            an=DNSRR(rrname="www.example.com", type="CNAME", ttl=300, rdata="example.com.") /
               DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
            ns=DNSRR(rrname="example.com", type="NS", ttl=300, rdata="ns1.example.com.") /
               DNSRR(rrname="example.com", type="NS", ttl=300, rdata="ns2.example.com."),
            ar=DNSRR(rrname="ns1.example.com", type="A", ttl=300, rdata="203.0.113.1") /
               DNSRR(rrname="ns2.example.com", type="A", ttl=300, rdata="203.0.113.2")
        )
    )


def build_fake_dns_response():
    return (
        IP(src="185.10.10.10", dst="192.168.1.5") /
        UDP(sport=53, dport=49532) /
        DNS(
            id=0x1234,
            qr=1,
            rd=1,
            qd=DNSQR(qname="www.example.com", qtype="A"),
            an=DNSRR(rrname="www.example.com", type="A", ttl=1, rdata="5.5.5.5"),
        )
    )


if __name__ == "__main__":
    handler = DnsSpoofingHandler()
    legit_pkt = build_legit_dns_response()
    fake_pkt = build_fake_dns_response()

    print("Legit packet detected as spoofed?:", handler.detect(legit_pkt))  # Expected: False
    print("Fake packet detected as spoofed?:", handler.detect(fake_pkt))    # Expected: True

