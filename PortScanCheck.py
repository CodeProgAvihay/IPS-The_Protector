from scapy.all import IP, TCP
from scapy.all import *
import time

TARGET_IP = "192.168.56.101"   # ה-IP של ה-VM המוגן
PORTS = range(20, 40)          # מספיק בשביל לעבור את ports_checked
DELAY = 0.1                    # בתוך time_window שלך

def syn_scan():
    print("[*] SYN scan")
    for port in PORTS:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(DELAY)

def fin_scan():
    print("[*] FIN scan")
    for port in PORTS:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="F")
        send(pkt, verbose=False)
        time.sleep(DELAY)

def null_scan():
    print("[*] NULL scan")
    for port in PORTS:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags=0)
        send(pkt, verbose=False)
        time.sleep(DELAY)

def xmas_scan():
    print("[*] XMAS scan")
    for port in PORTS:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="FPU")
        send(pkt, verbose=False)
        time.sleep(DELAY)

if __name__ == "__main__":
    syn_scan()
    time.sleep(2)

    fin_scan()
    time.sleep(2)

    null_scan()
    time.sleep(2)

    xmas_scan()