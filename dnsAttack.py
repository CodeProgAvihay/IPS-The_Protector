import scapy.all as scapy
from sqlDataBase import SqliteDatabase
from dnsSpoofingHandler import DnsSpoofingHandler

IP = scapy.IP
UDP = scapy.UDP
DNS = scapy.DNS
DNSQR = scapy.DNSQR
DNSRR = scapy.DNSRR
raw = scapy.raw

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


def dns_attack():
    db = SqliteDatabase()
    handler = DnsSpoofingHandler(db)
    legit_pkt = build_legit_dns_response()
    fake_pkt = build_fake_dns_response()

    print("Legit packet detected as spoofed?:", handler.detect(legit_pkt))  # Expected: False
    print("Fake packet detected as spoofed?:", handler.detect(fake_pkt))  # Expected: True


if __name__ == "__main__":
    dns_attack()