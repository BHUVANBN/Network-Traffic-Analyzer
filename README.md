# 🛡️ Sentinel | Enterprise Network Traffic Analyzer

<div align="center">
  <img src="dot-timeline-template-png.png" alt="Sentinel Logo" width="120" />
</div>

<p align="center">
  <strong>A sophisticated, Python-powered cybersecurity tool to capture, analyze, and visualize network traffic in real time.</strong>
</p>

---

## 🚀 Overview
**Sentinel** is a professional-grade network sniffer and analysis dashboard. Designed to mimic the core functionality of enterprise tools like Wireshark and advanced Security Information and Event Management (SIEM) dashboards, it provides deep, real-time insights into your network environment.

Built with **Scapy** for robust packet dissection, **Pandas** for high-speed data manipulation, and **Streamlit** for a stunning, responsive frontend, Sentinel acts as the ultimate network security camera for homelabs and educational environments.

---

## ✨ Key Features

### 📡 Core Networking
- **Live Packet Sniffing**: Continuous, real-time capturing using background threading.
- **Thread-Safe Architecture**: Employs an efficient `collections.deque` ring-buffer capable of maintaining a rolling log of up to 10,000 packets without memory leaks.
- **Protocol Support**: Decodes IPv4/IPv6, TCP, UDP, ICMP, and ARP traffic.

### 🧠 Threat Intelligence & Alerts
- **Dynamic Threat Detection**: Automatically identifies network anomalies.
  - **Port Scans**: Detects single IPs attempting to access numerous sequential or random ports.
  - **Traffic Floods**: Detects volumetric Denial-of-Service (DoS) behavior.
  - **SYN Floods**: Specifically targets half-open TCP connection attacks.
- **Configurable Sensitivity**: Adjust detection thresholds on the fly directly from the dashboard UI.
- **Alert Persistence & Export**: Maintains a full alert history log for the session.
- **SMTP Notifications**: Optionally trigger automatic email alerts to administrators for High-Severity threats.

### 📊 Advanced Analytics & Visualizations
- **Time-Series Monitoring**: Filled area charts graphing live network throughput (Packets / Second).
- **Deep Packet Analytics**:
  - **Packet Size Distributions**: Automatically groups and graphs packet payloads by byte size.
  - **TCP Flag Breakdowns**: Tracks SYN, ACK, FIN, PSH, URG, and RST flags.
  - **ICMP Type Breakdowns**: Categorizes Echo Requests, Echo Replies, and Destination Unreachable messages.
- **Top Talkers**: Live bar charts displaying the most active Source and Destination IP addresses.
- **DNS Query Tracking**: Performs Deep Packet Inspection (DPI) on UDP Port 53 to log and track requested domain names in real time.

### 🌍 Geolocation & Enrichment
- **Live World Map**: Plots public IP traffic on an interactive dark-themed Folium map.
- **Reverse DNS**: Uses local socket layers to resolve raw IP addresses back into readable Hostnames.
- **Intelligent IP Geolocation**: Connects to `ip-api.com` to resolve physical locations, utilizing an internal caching layer to strictly respect free-tier rate limits and automatically bypass local subnets.

### 🎨 UI & Quality of Life
- **Unified Navigation Bar**: All session KPIs, capture controls, and action buttons are accessible via a sleek, unified top bar.
- **Dark & Light Mode**: Seamless UI toggling via custom CSS injections.
- **Browser-Native Exports**: Instantly download your current 10,000-packet buffer directly to your browser as a UTF-8 CSV file.

---

## 🛠️ Installation

### 1. Prerequisites
- **Python**: Version 3.8 or newer.
- **Linux / macOS**: Application requires `sudo`/`root` privileges to bind raw network sockets for sniffing.
- **Windows**: Run your terminal as an **Administrator**. You must also have [Npcap](https://npcap.com/) installed on your machine.

### 2. Install Dependencies
Ensure you are in a virtual environment (recommended), then install the requirements:
```bash
pip install -r requirements.txt
```

### 3. Run the Application
Start the Streamlit dashboard by executing the main entry point:
```bash
sudo ./venv/bin/streamlit run main.py
```
*(Note: Use your specific virtual environment path or global `streamlit` binary as necessary.)*

---

## 📁 Project Architecture

- `main.py` — Application entry point.
- `display.py` — The core Streamlit frontend, containing the unified navbar and complex layout matrix.
- `capture.py` — The background Scapy sniffing engine and thread-safe data buffer.
- `analyzer.py` — Heavy Pandas analytics logic, data transformation, and grouping.
- `alert.py` — Security logic, dynamic thresholding, and threat modeling.
- `geoip.py` — Caching layer, reverse DNS hostname lookups, and Geolocation API logic.
- `dns_tracker.py` — Specific packet parsing to extract domain requests from DNS layers.
- `exporter.py` — In-memory conversion of raw packets to downloadable CSVs.
- `notifier.py` — SMTP email configuration and alert dispatching.

---

## ⚖️ Ethics, Scope, and Legality
**EDUCATIONAL AND HOMELAB USE ONLY.** 

Running this tool on networks you do not own, or networks where you do not have explicit administrative permission to perform security auditing, is **ILLEGAL**. 

This tool captures real, raw network packets. It is designed solely for learning about network protocols, building Python-based data pipelines, and understanding foundational cybersecurity threat behaviors.

---
*Built with Scapy, Pandas, Folium, and Streamlit.*
