# 🛡️ Real-Time Intrusion Prevention System (IPS)

## 📌 Overview

This project is a **Real-Time Intrusion Prevention System (IPS)** designed to monitor, analyze, and actively block malicious network traffic in a Linux environment.

The system operates at the **IP layer and below**, intercepting packets before they reach user-space applications using **iptables + NetfilterQueue (NFQUEUE)**. Each packet is analyzed in real time, and the system decides whether to allow or block it based on a set of detection engines.

When a malicious activity is detected, the system performs a full defensive response pipeline including:
- Immediate IP blocking
- Packet dropping at kernel interception level
- Logging attack details into a SQLite database
- Sending email alerts to the user
- Displaying CLI logs and real-time GUI notifications

This project simulates key mechanisms used in real-world **Intrusion Prevention Systems (IPS)** and provides hands-on experience in network security, packet inspection, and system-level defense mechanisms.

---

## ⚙️ Key Features

### 🔍 Real-Time Packet Interception
- Uses Linux **iptables + NetfilterQueue (NFQUEUE)** to intercept packets before they reach applications
- Works at the IP layer for low-level traffic control
- Processes packets in real time with minimal delay

---

### 🚨 Attack Detection Engine

The system detects and mitigates multiple types of network attacks:

- 📡 Port Scanning
- 💥 SYN Flood Attacks
- 🕵️ DNS Spoofing
- 🌐 DNS Tunneling

Each detection module is independently implemented and uses tailored logic depending on the nature of the attack.

---

### 🧠 Detection Methods

The IPS uses a hybrid detection approach:

- **Rule-based detection** → predefined signatures and conditions
- **Threshold-based detection** → packet rate and frequency analysis
- **Behavioral correlation** → analyzing patterns across multiple packets over time

Different attacks require different strategies:
- Single-packet analysis (e.g., DNS spoofing)
- Multi-packet correlation (e.g., port scanning, DNS tunneling)
- Rate analysis (e.g., SYN flood attacks)

---

### ⛔ Active Prevention System

When an attack is detected:
- The source IP is immediately blocked
- Malicious packets are dropped at the NFQUEUE layer
- Further communication from the attacker is prevented at the system level

---

### 📊 Logging & Forensics

All detected events are stored in a local **SQLite database**:

- Attack type
- Source IP address
- Timestamp
- Packet metadata (if applicable)

This enables later forensic analysis and attack reconstruction.

---

### 📧 Email Notification System

Each detected attack triggers an automated email alert containing:
- Type of attack
- Source IP
- Timestamp
- Short explanation of the event

---

### 🖥️ User Interface

The system provides multiple real-time interfaces:

- CLI logs for continuous monitoring
- Popup GUI notifications for immediate alerts

---

## 🏗️ System Architecture


Incoming Network Packet
↓
iptables (NFQUEUE interception)
↓
User-Space Packet Handler (Python)
↓
Detection Engine
↓
Decision Module
├── Allow Packet
├── Drop Packet
└── Block Source IP
↓
Response Layer
├── SQLite Logging
├── Email Notification
├── CLI Output
└── GUI Popup Alert


---

## 🧩 Attack Types

### 📡 Port Scan
Detects repeated connection attempts to multiple ports from a single IP within a short time window.

---

### 💥 SYN Flood
Detects abnormal spikes in SYN packets indicating potential denial-of-service behavior.

---

### 🕵️ DNS Spoofing
Identifies malicious or inconsistent DNS responses that do not match expected legitimate patterns.

---

### 🌐 DNS Tunneling
Detects abnormal DNS query behavior used for data exfiltration or covert communication channels.

---

## 🐧 System Requirements

### Operating System
- Linux (required due to NetfilterQueue + iptables dependency)

### Dependencies
- Python 3.x
- NetfilterQueue
- iptables
- SQLite3
- SMTP library (email notifications)

---

Each detected attack is stored with:

ID (auto-increment)
Timestamp
Source IP
Attack type
Packet metadata (optional JSON field)
🔐 Design Considerations
Why NetfilterQueue?

The system uses NFQUEUE to operate between kernel and user space, allowing:

Inline packet inspection before processing
Real-time blocking decisions
Full control over traffic flow
Trade-offs:
Requires root privileges
Linux-only implementation
Performance overhead due to user-space processing
📈 Future Improvements
Machine Learning-based anomaly detection
Advanced behavioral analysis engine
Web dashboard for monitoring attacks
Centralized SIEM integration
Distributed IPS architecture
IPv6 and deeper L7 inspection support
Risk scoring engine combining multiple detection signals
🎯 Project Goal

The goal of this project is to simulate a real-world Intrusion Prevention System while gaining deep practical experience in:

Network security and packet analysis
Linux networking stack internals
Real-time decision-making systems
Cybersecurity defense architectures
⚠️ Disclaimer

This project is developed for educational and research purposes only and is intended to demonstrate cybersecurity principles in a controlled environment.

👤 Author

Avihay Bababekov
