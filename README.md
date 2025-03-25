# 🔍 IOC Checker 🔍

![Python](https://img.shields.io/badge/python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-4.2-orange)

A robust security tool for analyzing **domains**, **URLs**, **hashes**, and **IP addresses** using VirusTotal and AbuseIPDB APIs with automatic defanging of malicious indicators.

## 📜 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
## 🌟 Features

- **Multi-type scanning**:
  - 🌐 Domain reputation analysis
  - 🔗 URL scanning (with redirect tracking)
  - 🔐 File hash verification
  - 📡 IP address reputation checks

- **Security-focused outputs**:
  - 🛡️ Automatic defanging of IOCs (URLs/Domains/IPs)
  - 📊 Structured CSV reports
  - ⚠️ Clear malicious/clean classification

- **Enterprise-ready**:
  - ⏱️ Built-in rate limiting
  - 🔄 Resume capability (partial results saved)
  - 📝 Detailed error logging

## 🚀 Installation

### Prerequisites
- Python 3.8+
- API keys from:
  - [VirusTotal](https://www.virustotal.com/)
  - [AbuseIPDB](https://www.abuseipdb.com/)

```bash
# Clone repository
git clone https://github.com/0x4hm3d/IOC-Checker.git
cd IOC-Checker

# Install dependencies
pip install -r requirements.txt

# Create config file
echo "[API_KEYS]" > config.ini
echo "virustotal = your_vt_api_key" >> config.ini
echo "abuseipdb = your_abuseipdb_api_key" >> config.ini

````
## 🖥️ Usage

### Basic Command
```bash
python3 ioc-checker.py 
![Uploading image.png…]()
