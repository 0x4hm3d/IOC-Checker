import requests
import time
import csv
from enum import Enum
import sys
import configparser
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

class ScanType(Enum):
    URL = 1
    DOMAIN = 2
    HASH = 3
    IP = 4

def display_banner():
    print("""

 ____  ___      __         __  __ __    ___     __  __  _    ___  ____  
l    j/   \    /  ]       /  ]|  T  T  /  _]   /  ]|  l/ ]  /  _]|    \ 
 |  TY     Y  /  /       /  / |  l  | /  [_   /  / |  ' /  /  [_ |  D  )
 |  ||  O  | /  /       /  /  |  _  |Y    _] /  /  |    \ Y    _]|    / 
 |  ||     |/   \_     /   \_ |  |  ||   [_ /   \_ |     Y|   [_ |    \ 
 j  ll     !\     |    \     ||  |  ||     T\     ||  .  ||     T|  .  Y
|____j\___/  \____j     \____jl__j__jl_____j \____jl__j\_jl_____jl__j\_j
                                                                        
        Author: \033[96mAhmed ElHabashi\033[0m
        X: \033[96m@iahmedelhabashy\033[0m
        Version: \033[96m IOC Checker v1.0 - URL/Domain/Hashes/IPs\033[0m
""")

def load_config():
    config = configparser.ConfigParser()
    config_file = Path('config.ini')
    
    if not config_file.exists():
        print("\nConfiguration file (config.ini) not found. Creating template...")
        config['API_KEYS'] = {
            'virustotal': 'your_virustotal_api_key_here',
            'abuseipdb': 'your_abuseipdb_api_key_here'
        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        print("Created config.ini template. Please edit it with your API keys.")
        sys.exit(1)
    
    try:
        config.read('config.ini')
        return {
            'virustotal': config['API_KEYS'].get('virustotal'),
            'abuseipdb': config['API_KEYS'].get('abuseipdb')
        }
    except KeyError as e:
        print(f"\nError in config.ini: Missing section or key - {str(e)}")
        print("Please ensure your config.ini has [API_KEYS] section with virustotal and abuseipdb keys")
        sys.exit(1)

def read_txt_file(file_path):
    try:
        with open(file_path, 'r') as file:
            items = [line.strip() for line in file if line.strip()]
        return items
    except FileNotFoundError:
        print(f"\nError: File not found - {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"\nError reading file: {str(e)}")
        sys.exit(1)

def select_scan_type():
    print("\nSelect scan type:")
    print("1. URL Scan (VirusTotal)")
    print("2. Domain Scan (VirusTotal)")
    print("3. Hash Scan (VirusTotal)")
    print("4. IP Address Scan (AbuseIPDB)")
    print("5. Exit")
    
    try:
        choice = int(input("Enter your choice (1-5): "))
        if choice == 5:
            sys.exit(0)
        return ScanType(choice)
    except ValueError:
        print("Invalid input. Please enter a number between 1-5.")
        return select_scan_type()

def defang_indicator(indicator):
    """Safety format URLs, domains, and IPs for reporting"""
    if not isinstance(indicator, str):
        return indicator
        
    # Defang URLs (http -> hxxp)
    if indicator.startswith(('http://', 'https://')):
        return indicator.replace('http', 'hxxp').replace('.', '[.]')
    
    # Defang IP addresses
    if any(char.isdigit() for char in indicator) and '.' in indicator:
        parts = indicator.split('.')
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            return '[.]'.join(parts)
    
    # Defang domains
    if '.' in indicator and not indicator.startswith(('http', 'www')):
        return indicator.replace('.', '[.]')
    
    return indicator

def initialize_csv(file_path, fieldnames):
    try:
        with open(file_path, 'r') as f:
            pass
    except FileNotFoundError:
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

def virus_total_url_scan(file_path, api_key):
    urls = read_txt_file(file_path)
    vt_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    
    url_fields = [
        'url', 'scan_date', 'response_code', 'positives', 'total',
        'permalink', 'final_url', 'redirect_count', 'http_status',
        'content_type', 'first_seen', 'last_seen', 'status',
        'detected_engines'
    ]
    
    initialize_csv('virustotal_urls.csv', url_fields)
    
    print(f"\nStarting URL scan for {len(urls)} items...")
    for i, url in enumerate(urls, 1):
        defanged_url = defang_indicator(url)
        print(f"Processing {i}/{len(urls)}: {defanged_url}")
        
        try:
            response = requests.get(
                vt_url,
                params={'apikey': api_key, 'resource': url},
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            detected_engines = []
            if isinstance(data, dict) and 'scans' in data:
                detected_engines = [engine for engine, result in data.get('scans', {}).items() 
                                  if isinstance(result, dict) and result.get('detected', False)]
            
            row = {
                'url': defanged_url,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'response_code': data.get('response_code', -1) if isinstance(data, dict) else -1,
                'positives': data.get('positives', 0) if isinstance(data, dict) else 0,
                'total': data.get('total', 0) if isinstance(data, dict) else 0,
                'permalink': defang_indicator(data.get('permalink', '')) if isinstance(data, dict) else '',
                'final_url': defang_indicator(data.get('final_url', '')) if isinstance(data, dict) else '',
                'redirect_count': len(data.get('redirects', [])) if isinstance(data, dict) and isinstance(data.get('redirects', []), list) else 0,
                'http_status': data.get('http_status', '') if isinstance(data, dict) else '',
                'content_type': data.get('content_type', '') if isinstance(data, dict) else '',
                'first_seen': data.get('first_seen', '') if isinstance(data, dict) else '',
                'last_seen': data.get('last_seen', '') if isinstance(data, dict) else '',
                'status': 'clean' if isinstance(data, dict) and data.get('positives', 0) <= 0 else 'malicious',
                'detected_engines': ', '.join(detected_engines)
            }
            
            with open('virustotal_urls.csv', 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=url_fields)
                writer.writerow(row)
            
            print(f"  Result: {row['positives']}/{row['total']} detections ({row['status']})")
            
        except requests.exceptions.RequestException as e:
            print(f"  Error: {str(e)}")
            error_row = {
                'url': defanged_url,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'error',
                'verbose_msg': str(e)
            }
            with open('virustotal_urls.csv', 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=url_fields)
                writer.writerow({**{field: '' for field in url_fields}, **error_row})
        
        if i < len(urls):
            time.sleep(16)

def virus_total_domain_scan(file_path, api_key):
    domains = read_txt_file(file_path)
    vt_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    
    domain_fields = [
        'domain', 'scan_date', 'response_code', 'categories',
        'subdomains', 'registrar', 'creation_date', 'last_update',
        'country', 'detected_urls', 'detected_samples', 'status',
        'verbose_msg'
    ]
    
    initialize_csv('virustotal_domains.csv', domain_fields)
    
    print(f"\nStarting Domain scan for {len(domains)} items...")
    for i, domain in enumerate(domains, 1):
        defanged_domain = defang_indicator(domain)
        print(f"Processing {i}/{len(domains)}: {defanged_domain}")
        
        try:
            response = requests.get(
                vt_url,
                params={'apikey': api_key, 'domain': domain},
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            if not isinstance(data, dict):
                raise ValueError("Invalid response format")
            
            whois_data = data.get('whois', {}) if isinstance(data.get('whois'), dict) else {}
            detected_urls = data.get('detected_urls', [])
            detected_samples = data.get('detected_downloaded_samples', [])
            
            row = {
                'domain': defanged_domain,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'response_code': data.get('response_code', -1),
                'categories': ', '.join(data.get('categories', [])) if isinstance(data.get('categories'), list) else '',
                'subdomains': ', '.join([defang_indicator(sub) for sub in data.get('subdomains', []) 
                                       if isinstance(sub, str)]),
                'registrar': whois_data.get('registrar', ''),
                'creation_date': whois_data.get('creation_date', ''),
                'last_update': whois_data.get('updated_date', ''),
                'country': data.get('country', ''),
                'detected_urls': len(detected_urls) if isinstance(detected_urls, list) else 0,
                'detected_samples': len(detected_samples) if isinstance(detected_samples, list) else 0,
                'status': 'suspicious' if (isinstance(detected_urls, list) and len(detected_urls) > 0) or 
                                        (isinstance(detected_samples, list) and len(detected_samples) > 0) else 'clean',
                'verbose_msg': data.get('verbose_msg', 'OK')
            }
            
            with open('virustotal_domains.csv', 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=domain_fields)
                writer.writerow(row)
            
            print(f"  Result: {row['detected_urls']} malicious URLs, {row['detected_samples']} malicious samples ({row['status']})")
            
        except requests.exceptions.RequestException as e:
            print(f"  Error: {str(e)}")
            error_row = {
                'domain': defanged_domain,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'error',
                'verbose_msg': str(e)
            }
            with open('virustotal_domains.csv', 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=domain_fields)
                writer.writerow({**{field: '' for field in domain_fields}, **error_row})
        
        if i < len(domains):
            time.sleep(16)

def virus_total_hash_scan(file_path, api_key):
    hashes = read_txt_file(file_path)
    vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    
    hash_fields = [
        'hash', 'scan_date', 'response_code', 'positives', 'total',
        'permalink', 'sha1', 'sha256', 'md5', 'file_type',
        'first_seen', 'last_seen', 'times_submitted', 'status',
        'detected_engines'
    ]
    
    initialize_csv('virustotal_hashes.csv', hash_fields)
    
    print(f"\nStarting hash scan for {len(hashes)} items...")
    for i, hash_item in enumerate(hashes, 1):
        print(f"Processing {i}/{len(hashes)}: {hash_item}")
        
        try:
            response = requests.get(
                vt_url,
                params={'apikey': api_key, 'resource': hash_item},
                headers={'User-Agent': 'Mozilla/5.0'},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            detected_engines = []
            if isinstance(data, dict) and 'scans' in data:
                detected_engines = [engine for engine, result in data['scans'].items() 
                                  if isinstance(result, dict) and result.get('detected', False)]
            
            row = {
                'hash': hash_item,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'response_code': data.get('response_code', -1),
                'positives': data.get('positives', 0),
                'total': data.get('total', 0),
                'permalink': defang_indicator(data.get('permalink', '')),
                'sha1': data.get('sha1', ''),
                'sha256': data.get('sha256', ''),
                'md5': data.get('md5', ''),
                'file_type': data.get('type', ''),
                'first_seen': data.get('first_seen', ''),
                'last_seen': data.get('last_seen', ''),
                'times_submitted': data.get('times_submitted', 0),
                'status': 'clean' if data.get('positives', 0) <= 0 else 'malicious',
                'detected_engines': ', '.join(detected_engines)
            }
            
            with open('virustotal_hashes.csv', 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=hash_fields)
                writer.writerow(row)
            
            print(f"  Result: {row['positives']}/{row['total']} detections ({row['status']})")
            
        except requests.exceptions.RequestException as e:
            print(f"  Error: {str(e)}")
            error_row = {
                'hash': hash_item,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'error',
                'verbose_msg': str(e)
            }
            with open('virustotal_hashes.csv', 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=hash_fields)
                writer.writerow({**{field: '' for field in hash_fields}, **error_row})
        
        if i < len(hashes):
            time.sleep(16)

def abuseipdb_scan(file_path, api_key):
    ips = read_txt_file(file_path)
    api_url = 'https://api.abuseipdb.com/api/v2/check'
    
    ip_fields = [
        'ipAddress', 'scan_date', 'isPublic', 'ipVersion', 'isWhitelisted',
        'abuseConfidenceScore', 'countryCode', 'countryName', 'region',
        'city', 'isp', 'domain', 'hostnames', 'totalReports',
        'numDistinctUsers', 'lastReportedAt', 'isTor', 'status'
    ]
    
    initialize_csv('abuseipdb_results.csv', ip_fields)
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    print(f"\nStarting IP scan for {len(ips)} items...")
    for i, ip_item in enumerate(ips, 1):
        defanged_ip = defang_indicator(ip_item)
        print(f"Processing {i}/{len(ips)}: {defanged_ip}")
        
        try:
            response = requests.get(
                api_url,
                headers=headers,
                params={'ipAddress': ip_item, 'maxAgeInDays': '90'},
                timeout=30
            )
            response.raise_for_status()
            data = response.json().get('data', {})
            
            if not isinstance(data, dict):
                raise ValueError("Invalid response format")
            
            row = {
                'ipAddress': defanged_ip,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'isPublic': data.get('isPublic', ''),
                'ipVersion': data.get('ipVersion', ''),
                'isWhitelisted': data.get('isWhitelisted', False),
                'abuseConfidenceScore': data.get('abuseConfidenceScore', 0),
                'countryCode': data.get('countryCode', ''),
                'countryName': data.get('countryName', ''),
                'region': data.get('region', ''),
                'city': data.get('city', ''),
                'isp': data.get('isp', ''),
                'domain': defang_indicator(data.get('domain', '')),
                'hostnames': ', '.join([defang_indicator(host) for host in data.get('hostnames', []) 
                                      if isinstance(host, str)]),
                'totalReports': data.get('totalReports', 0),
                'numDistinctUsers': data.get('numDistinctUsers', 0),
                'lastReportedAt': data.get('lastReportedAt', ''),
                'isTor': data.get('isTor', False),
                'status': 'suspicious' if data.get('abuseConfidenceScore', 0) > 0 else 'clean'
            }
            
            with open('abuseipdb_results.csv', 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=ip_fields, extrasaction='ignore')
                writer.writerow(row)
            
            print(f"  Result: Confidence {row['abuseConfidenceScore']}% ({row['status']})")
            
        except requests.exceptions.RequestException as e:
            print(f"  Error: {str(e)}")
            error_row = {
                'ipAddress': defanged_ip,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'error',
                'verbose_msg': str(e)
            }
            with open('abuseipdb_results.csv', 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=ip_fields, extrasaction='ignore')
                writer.writerow({**{field: '' for field in ip_fields}, **error_row})
        
        if i < len(ips):
            time.sleep(1)

def main():
    display_banner()
    config = load_config()
    
    try:
        file_path = input('\nPlease enter the TXT file PATH: ')
        scan_type = select_scan_type()
        output_file = ""
        
        if scan_type == ScanType.URL:
            virus_total_url_scan(file_path, config['virustotal'])
            output_file = "virustotal_urls.csv"
        elif scan_type == ScanType.DOMAIN:
            virus_total_domain_scan(file_path, config['virustotal'])
            output_file = "virustotal_domains.csv"
        elif scan_type == ScanType.HASH:
            virus_total_hash_scan(file_path, config['virustotal'])
            output_file = "virustotal_hashes.csv"
        elif scan_type == ScanType.IP:
            abuseipdb_scan(file_path, config['abuseipdb'])
            output_file = "abuseipdb_results.csv"
        
        print(f"\nScan completed successfully! Output file: {output_file}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Partial results saved.")
    except Exception as e:
        print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()
