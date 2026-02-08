# import signal
import sys
import os
import time
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
from portScanningHandller import PortScanningHandler
from dnsSpoofingHandler import DnsSpoofingHandler
from SYNFloodHandler import SynFloodHandler
from sqlDataBase import SqliteDatabase
import system_status

IP = scapy.IP

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
    # sys.exit(0)


def clousre_to_process(HANDLERS):
    def process_packet(packet):
        try:
            scapy_pck = IP(packet.get_payload())
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
    return process_packet


def main():
    require_root()
    os.system("iptables -I INPUT -j NFQUEUE --queue-num 1")
    nfqueue = NetfilterQueue()
    DB = SqliteDatabase()
    HANDLERS = [
    PortScanningHandler(DB),
    SynFloodHandler(DB),
    DnsSpoofingHandler(DB)
    ]
    # checking when the program closed:
    # signal.signal(signal.SIGINT, lambda s, f: cleanup_and_exit(nfqueue, s, f)) #by Ctrl + C
    # signal.signal(signal.SIGTERM, lambda s, f: cleanup_and_exit(nfqueue, s, f)) #by killing the terminal.
    # signal.signal(signal.SIGHUP, lambda s, f: cleanup_and_exit(nfqueue, s, f)) #by disconnecting from the terminal.
    process_func = clousre_to_process(HANDLERS)
    nfqueue.bind(1, process_func)
    print("Starting listennig to packets...")
    try:
        while system_status.running:
            nfqueue.run(block=False)
            time.sleep(0.05)
    finally:
        cleanup_and_exit(nfqueue)

    cleanup_and_exit(nfqueue)
