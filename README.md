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
- [Contributing](#-contributing)
- [License](#-license)

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
🖥️ Usage
bash
Copy
python3 ioc-checker.py -i input_file.txt -o results.csv
Command-line Options:
Copy
-i, --input    Input file containing IOCs (one per line)
-o, --output   Output CSV file for results
-v, --verbose  Show detailed processing information
-r, --resume   Continue from last saved state
📊 Output Samples
URL Scan (virustotal_urls.csv)
csv
Copy
url,scan_date,positives,total,status,final_url
hxxp://evil[.]com,2023-08-20 14:30:00,45,72,malicious,hxxp://redirect[.]evil[.]com
hxxps://safe[.]org,2023-08-20 14:30:16,0,72,clean,hxxps://safe[.]org/login
IP Scan (abuseipdb_report.csv)
csv
Copy
ip_address,abuse_score,country,usage_type,domain,is_whitelisted,reported_times
192.168.1.1,98%,US,"Data Center/Web Hosting",evil.net,False,142
10.0.0.1,5%,CA,Corporate,company.com,True,2
🚧 Future Enhancements
Add hybrid analysis integration

Implement asynchronous scanning

Add GUI interface option

Support for additional IOC types (email, registry keys)

Docker container deployment

🤝 Contributing
Fork the repository

Create your feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

📄 License
Distributed under the MIT License. See LICENSE for more information.
