from scapy.all import DNS, DNSQR, IP, UDP
from scapy.all import *
import base64
import random
import string
import time

TARGET_DNS = "192.168.56.101"   # שנה ל-IP של השרת / VM המוגנת
DOMAIN = "example.com"

def random_data(size=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size))

def encode_data(data):
    encoded = base64.b32encode(data.encode()).decode()
    return encoded.strip("=")

def send_dns_tunnel():
    while True:
        data = random_data(30)
        encoded = encode_data(data)

        subdomain = f"{encoded}.{DOMAIN}"

        packet = (
            IP(dst=TARGET_DNS) /
            UDP(dport=53) /
            DNS(
                rd=1,
                qd=DNSQR(qname=subdomain)
            )
        )

        send(packet, verbose=False)

        time.sleep(0.02)  # 20ms בין חבילות (~50 לשנייה)

if __name__ == "__main__":
    print("Starting DNS Tunnel Simulation...")
    send_dns_tunnel()