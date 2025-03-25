# 🔍 IOC Checker 🔍

![Python](https://img.shields.io/badge/python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-4.2-orange)

A robust security tool for analyzing **domains**, **URLs**, **hashes**, and **IP addresses** using VirusTotal and AbuseIPDB APIs with automatic defanging of malicious indicators.

## 📜 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Samples](#-output-samples)
- [Future Enhancements](#-future-enhancements)
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
 ____  ___      __         __  __ __    ___     __  __  _    ___  ____  
l    j/   \    /  ]       /  ]|  T  T  /  _]   /  ]|  l/ ]  /  _]|    \ 
 |  TY     Y  /  /       /  / |  l  | /  [_   /  / |  ' /  /  [_ |  D  )
 |  ||  O  | /  /       /  /  |  _  |Y    _] /  /  |    \ Y    _]|    / 
 |  ||     |/   \_     /   \_ |  |  ||   [_ /   \_ |     Y|   [_ |    \ 
 j  ll     !\     |    \     ||  |  ||     T\     ||  .  ||     T|  .  Y
|____j\___/  \____j     \____jl__j__jl_____j \____jl__j\_jl_____jl__j\_j
                                                                        
        Author: Ahmed ElHabashi
        X: @iahmedelhabashy
        Version:  IOC Checker v1.0 - URL/Domain/Hashes/IPs


Please enter the TXT file PATH:

```
📁 **Output Files**:

1. **URL Scan** (`virustotal_urls.csv`):
   - `url` (Defanged)
   - `final_url` (Defanged)
   - `positives/total` detections
   - `status` (clean/malicious)
   - `redirect_count`, `http_status`, `detected_engines`
   *Example*:  
   `hxxp://evil[.]com, hxxp://redirect[.]evil[.]com, 45/72, malicious, 3, 301, "ESET, Kaspersky"`

2. **Domain Scan** (`virustotal_domains.csv`):
   - `domain` (Defanged)
   - `detected_urls/samples`
   - `subdomains` (Defanged)
   - `registrar`, `country`, `status`
   *Example*:  
   `evil[.]com, 12, 5, "sub1[.]evil[.]com", NameCheap, RU, suspicious`

3. **Hash Scan** (`virustotal_hashes.csv`):
   - `hash`
   - `file_type`, `first/last_seen`
   - `positives/total`, `status`
   - `detected_engines`
   *Example*:  
   `d41d8cd98f...7e, PE32, 2023-01-01, 55/70, malicious, "CrowdStrike, Microsoft"`

4. **IP Scan** (`abuseipdb_results.csv`):
   - `ipAddress` (Defanged)
   - `abuseConfidenceScore`
   - `country`, `isp`, `isTor`
   - `totalReports`, `status`
   *Example*:  
   `1[.]2[.]3[.]4, 98%, US, EvilISP, true, 142, suspicious`

🔍 **Key Features**:
- All IOCs automatically defanged in outputs
- Status indicators: `clean/malicious/suspicious/error`
- Error logging with timestamps in CSV
- Rate-limited API calls (15s VT / 1s AbuseIPDB)

🚧 **Future Enhancements

- Batch processing for large datasets
- JSON output option
- Integration with MISP/TheHive
- GUI interface (PyQt/Tkinter)
- Docker container deployment
- Asynchronous scanning for performance
========================================================================
