#!/usr/bin/env python3
import yaml
import argparse
from datetime import datetime
from nmap_wrapper import NmapScanner
from nuclei_wrapper import NucleiScanner
from zap_wrapper import ZAPScanner
from report_generator import generate_report
import os
import sys

def load_config(config_path='config/config.yaml'):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def setup_directories(scan_id):
    dirs = [
        f"outputs/nmap/{scan_id}",
        f"outputs/nuclei/{scan_id}",
        f"outputs/zap/{scan_id}",
        f"reports/{scan_id}"
    ]
    for dir in dirs:
        os.makedirs(dir, exist_ok=True)

def main():
    parser = argparse.ArgumentParser(description='Advanced Security Scanner')
    parser.add_argument('-t', '--target', help='Target to scan')
    parser.add_argument('-c', '--config', help='Custom config file')
    args = parser.parse_args()

    config = load_config(args.config if args.config else 'config/config.yaml')
    if args.target:
        config['target'] = args.target

    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    setup_directories(scan_id)

    print(f"[*] Starting scan for {config['target']} with ID: {scan_id}")

    # NMAP Scan
    print("[*] Running NMAP scan...")
    nmap = NmapScanner(config, scan_id)
    nmap_results = nmap.run_scan()

    # Nuclei Scan
    print("[*] Running Nuclei scan...")
    nuclei = NucleiScanner(config, scan_id)
    nuclei_results = nuclei.run_scan(nmap_results)

    # ZAP Scan (if web ports found)
    zap_results = None
    if nmap_results.get('web_ports'):
        print("[*] Running ZAP scan...")
        zap = ZAPScanner(config, scan_id)
        zap_results = zap.run_scan(nmap_results)
    else:
        print("[!] No web ports found, skipping ZAP scan")

    # Generate Report
    print("[*] Generating report...")
    generate_report(scan_id, config, nmap_results, nuclei_results, zap_results)

    print(f"[+] Scan completed! Report saved to reports/{scan_id}")

if __name__ == "__main__":
    main()
