from scapy.all import IP, TCP, send
import time
import random

TARGET_IP = "192.168.56.101"
TARGET_PORT = 80
COUNT = 200
RATE = 50


def send_syn_burst():
    print(f"[+] Sending {COUNT} SYN packets to {TARGET_IP}:{TARGET_PORT} at ~{RATE}/sec")

    delay = 1.0 / RATE

    for i in range(COUNT):
        sport = random.randint(1024, 65535)  # מקור אקראי כדי לדמות לקוחות שונים
        pkt = IP(dst=TARGET_IP) / TCP(sport=sport, dport=TARGET_PORT, flags="S")
        send(pkt, verbose=False)
        time.sleep(delay)

    print("[+] Done")

if __name__ == "__main__":
    send_syn_burst()