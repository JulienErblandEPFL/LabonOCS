# 📡 ARP & DNS Spoofing Tool with SSL Stripping

This is a fully automated Man-in-the-Middle (MITM) attack tool built in Python using Scapy. It performs ARP spoofing, DNS spoofing, and optional SSL stripping within a local network.

## ⚙️ Features

- ARP spoofing between victim and gateway
- DNS spoofing to redirect specific domains
- Optional SSL stripping (using `sslstrip` or `mitmproxy`)
- Simple interface and plug-and-play automation

## 🖥️ Setup

```bash
pip install -r requirements.txt
sudo python3 main.py