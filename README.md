# 🔍 IOC Checker 🔍

![Python](https://img.shields.io/badge/python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-4.2-orange)

A comprehensive threat intelligence tool for automated Indicator of Compromise (IOC) analysis.

## 📜 Table of Contents
- [Key Capabilities](#-key-capabilities)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Files](#-output-files)

## 📌 Key Capabilities
### Multi-IOC Support:
- 🌐 Domains: Reputation checks via VirusTotal
- 🔗 URLs: Scan for malware/phishing with redirect tracing
- 📡 IPs: Abuse detection with geolocation (AbuseIPDB)
- 🔐 Hashes (MD5/SHA-1/SHA-256): Malware verdicts from 70+ AV engines
### Enterprise-Grade Features:
- 🛡️ Auto-Defanging: Safely renders malicious IOCs (e.g., hxxp://evil[.]com)
- 📊 Bulk Processing: CSV input support for large-scale analysis
- 🔄 Resumable Scans: Saves progress for interrupted operations
- ⏱️ Rate Limiting: Complies with API quotas (VT: 4 req/min, AbuseIPDB: 1k/day)
### Actionable Outputs:
- Terminal Alerts: With the result (Malicious, Suspicious, Clean)
- Structured Reports:
```bash
📂 results/
├── virustotal_domains.csv  # Domain reputation  
├── virustotal_urls.csv     # URL scan results  
├── virustotal_hashes.csv   # File hash analysis  
└── abuseipdb_report.csv    # IP threat intelligence
```  
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
