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
        scapy_pck = Ether(packet.get_payload())
        if DB.does_address_exist(packet[IP].src):
            packet.drop()
            print("Dropped the attack.")
            return
        #print(scapy_pck)
        for handler in HANDLERS:
            if handler.detect(scapy_pck):
                packet.drop()
                print("Dropped the attack.")
                return
        packet.accept()
        print("packet got accepted")
    except Exception as e:
        print("Error analyze the packet.")
        packet.accpet()

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