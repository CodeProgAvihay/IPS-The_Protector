import signal
import re
import os
import sys
import time
import threading
import IP_IPS
import system_status

def require_root():
    if os.geteuid() != 0:
        print("[X] You must run the program with root permissions(sudo).")
        sys.exit(1)

def shutdown(thread, sig=None, frame=None):
    system_status.running = False
    thread.join()

def is_valid_email(email: str) -> bool:
    pattern = r'^(?!\.)[A-Za-z0-9._%+-]+(?<!\.)@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    return re.match(pattern, email) is not None

def main():
    require_root()

    print("Welcome to The Protector!!")
    email = input("\nBefore we start, please give us your email, so we could infrom you: ")
    while not is_valid_email(email):
        print("You entered something that is not an email!!")
        email = input("Please try again: ")
    
    th = threading.Thread(target=IP_IPS.main, args=(email,))
    th.start()

    #checking when the program closed:
    #signal.signal(signal.SIGINT, lambda s, f: shutdown(th, s, f))   #by Ctrl + C.
    #signal.signal(signal.SIGTERM, lambda s, f: shutdown(th, s, f))   #by killing the terminal.

    print("The system start running!!!\n\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        system_status.running = False
        th.join()

if __name__ == "__main__":
    main()
