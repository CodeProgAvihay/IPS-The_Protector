import os
from netfilterqueue import NetfilterQueue
from scapy.all import Ether

def process_packet(packet):
    pass

def main():
    os.system("iptables -I INPUT -j NFQUEUE --queue-num 1")
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        os.system("iptables -F")


if __name__ == "__main__":
    main()