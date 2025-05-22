# METIS - Monitoring Endpoint Traffic Intelligence System

**METIS** is a 3D network traffic visualization tool designed for home and educational environments.  
It uses Unity to visualize network nodes and traffic flows, while Python (Scapy) monitors and analyzes packets in real time.

> 📩 Feedback or questions? Contact us:  
> Email: `vanson.norton0506@icluod.com`  
> [日本語版はこちら（Japanese README）](https://github.com/bastyn0506/METIS/blob/main/README.md)

⚠️ **Disclaimer**  
This tool is intended for **educational and research purposes only**.  
Use in production environments is at your own risk. METIS is designed to raise security awareness and help users understand network traffic behavior.

---

## 🔰 Key Features

### 🐍 Python (packet_sniffer.py)
- Real-time packet capture with Scapy
- Automatic detection of traffic to dangerous ports (e.g., port 23)
- Basic port scan detection (multiple ports accessed in a short time)
- Extraction of **SNI** and **TLS version** from SSL/TLS traffic
- **IoC matching** (IP/domain/URL feed from CIRCL's ThreatFox)
- **Tor exit node detection** (based on GitHub-hosted exit lists)
- Live configuration reload from `config.json`
- Real-time data transfer to Unity via WebSocket
- Logging in JSON Lines format

### 🎮 Unity (3D Visualization)
- Visualizes source/destination IPs as 3D nodes
- Animates traffic between nodes as packet effects
- Highlights dangerous traffic in red
- Displays threat scores under nodes (via TextMeshPro)
- Allows configuration (dangerous ports, trusted IPs, etc.) via settings UI

---

## 🧩 Architecture Overview

- **Python**: Captures, analyzes, and transmits network traffic
- **Unity**: Receives and visualizes the data in real time
- Supports multi-device deployments (e.g., VPS → local PC)

---

## 🚀 Planned Features

- Automatic IoC synchronization with MISP
- File hash detection (e.g., SHA256)
- SSL certificate visibility
- Advanced scoring engine
- Educational use case packaging for classroom environments

---

## ⚙️ How It Works

