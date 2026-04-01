# 🛡️ Sentinel | Network Traffic Analyzer

A sophisticated, Python-powered cybersecurity tool to capture, analyze, and visualize network traffic in real time.

## 🚀 Key Features
- **Live Packet Capture**: Real-time sniffing from network interfaces (Root/Admin required).
- **Security Alerts**: Automatically detects Port Scanning and Flooding attacks.
- **Protocol Distribution**: Interactive visualization of TCP, UDP, ICMP, and other protocol usage.
- **Top Talkers**: Identifies and graphs the most active source/destination IP addresses.
- **IP Geolocation**: Categorizes IPs based on geographical location (using ip-api).
- **Data Export**: Save captured packet logs to a CSV file for deep forensics.
- **Premium UI**: Dark-themed, glassmorphism-inspired Streamlit dashboard.

---

## 🛠️ Installation

### 1. Prerequisites
- **Linux/macOS**: `sudo` access is required for packet sniffing.
- **Windows**: Run terminal as **Administrator**. [Npcap](https://npcap.com/) must be installed.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
From the `network_analyzer` directory, run:
```bash
sudo streamlit run main.py
```

---

## 📁 Project Structure
- `main.py`: Entry point for the dashboard.
- `capture.py`: Scapy logic for packet sniffing in a background thread.
- `analyzer.py`: Pandas analysis logic for statistics.
- `alert.py`: Pattern detection logic for suspicious activity.
- `geoip.py`: IP geolocation lookup using internal rules and public APIs.
- `display.py`: Streamlit-based interactive UI with custom CSS.
- `exporter.py`: Logic to export logs as CSV files.

---

## ⚖️ Ethics and Legality
**EDUCATIONAL USE ONLY.** 
Running this tool on networks you do not own or have explicit permission to audit is ILLEGAL. This tool is designed for home lab environments and learning about networking protocols.

---
*Built with Scapy, Pandas, and Streamlit.*
