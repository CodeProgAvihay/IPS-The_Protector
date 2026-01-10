import signal
import sys
import os
from netfilterqueue import NetfilterQueue
from scapy.all import Ether, IP
from portScanningHandller import PortScanningHandler
from dnsSpoofingHandler import DnsSpoofingHandler
from sqlDataBase import  SqliteDatabase

DB = SqliteDatabase()

HANDLERS = [
    PortScanningHandler(DB),
    DnsSpoofingHandler(DB)
]

blocked_ip = set()

def require_root():
    if os.geteuid() != 0:
        print("[X] You must run the program with root permissions(sudo).")
        sys.exit(1)

def cleanup_and_exit(nfqueue, signum=None, frame=None):
    try:
        nfqueue.unbind()
    except Exception as e:
        pass
    os.system("iptables -F")
    sys.exit(0)

def process_packet(packet):
    try:
        scapy_pck = IP(packet.get_payload())
        if not scapy_pck.haslayer(IP):
            print("Don't have IP.")
            packet.accept()
            return
        if scapy_pck[IP].src == "192.168.1.15":
            print("[*] Packet of check.")
        if scapy_pck[IP].src in blocked_ip:
            packet.drop()
            print("{&} Dropped the attack before checking.")
            return
        for handler in HANDLERS:
            if handler.detect(scapy_pck):
                packet.drop()
                blocked_ip.add(scapy_pck[IP].src)
                print("Dropped the attack.")
                return
        packet.accept()
        print("packet got accepted")
    except Exception as e:
        print("Error analyze the packet.")
        print("Error:", e)
        packet.accept()

def main():
    require_root()
    os.system("iptables -I INPUT -j NFQUEUE --queue-num 1")
    nfqueue = NetfilterQueue()

    #checking when the program closed:
    signal.signal(signal.SIGINT, lambda s, f: cleanup_and_exit(nfqueue, s, f)) #by Ctrl + C
    signal.signal(signal.SIGTERM, lambda s, f: cleanup_and_exit(nfqueue, s, f)) #by killing the terminal.
    signal.signal(signal.SIGHUP, lambda s, f: cleanup_and_exit(nfqueue, s, f)) #by disconnecting from the terminal.

    nfqueue.bind(1, process_packet)
    print("Starting listennig to packets...")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
       cleanup_and_exit(nfqueue)


if __name__ == "__main__":
    main()