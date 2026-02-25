# import signal
import sys
import os
import time
import smtplib
import threading
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
from portScanningHandller import PortScanningHandler
from dnsSpoofingHandler import DnsSpoofingHandler
from SYNFloodHandler import SynFloodHandler
from sqlDataBase import SqliteDatabase
from alert_manager import alert_queue
import sendEmail
import system_status

IP = scapy.IP
SYSTEM_GMAIL = "theprotsys@gmail.com"
SYSTEM_APP_PASSWORD = "eykafjfnujcvnfog"

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


def clousre_to_process(HANDLERS, email):
    def process_packet(packet):
        try:
            scapy_pck = IP(packet.get_payload())
            if scapy_pck[IP].src in blocked_ip:
                packet.drop()
                #print("{&} Dropped the attack before checking.")
                return
            for handler in HANDLERS:
                if handler.detect(scapy_pck, email):
                    packet.drop()
                    blocked_ip.add(scapy_pck[IP].src)
                    #print("Dropped the attack.")
                    return
            packet.accept()
            #print("packet got accepted")
        except Exception as e:
            print("Error analyze the packet.")
            print("Error:", e)
            packet.accept()
    return process_packet


def main(email):
    #require_root()
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(SYSTEM_GMAIL, SYSTEM_APP_PASSWORD)
    print("Connected to SMTP succssecfully.")
    mail_thread = threading.Thread(target=sendEmail.mail_worker, args=(server,))
    mail_thread.start()
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
    process_func = clousre_to_process(HANDLERS, email)
    nfqueue.bind(1, process_func)
    print("Starting listennig to packets...")
    try:
        while system_status.running:
            nfqueue.run(block=False)
            time.sleep(0.05)
    finally:
        #print("[*] Stopping IPS...")
        alert_queue.put(None)
        mail_thread.join()
        cleanup_and_exit(nfqueue)
        server.quit()
        print("[*] IPS stopped cleanly")
