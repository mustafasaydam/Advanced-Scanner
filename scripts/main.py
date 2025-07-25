#!/usr/bin/env python3
import yaml
from datetime import datetime
from nmap_automator import NmapAutomator
from nuclei_automator import NucleiAutomator
from zap_automator import ZAPAutomator
from report_engine import ReportEngine
from notification import Notifier
from integrations.amass import AmassScanner
from integrations.subfinder import SubfinderScanner
from integrations.dirsearch import DirsearchScanner
import os
import sys

class SecurityScanner:
    def __init__(self):
        self.config = self.load_config()
        self.notifier = Notifier(self.config)
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.setup_directories()
        
    def load_config(self):
        with open('config/config.yaml', 'r') as f:
            return yaml.safe_load(f)
    
    def setup_directories(self):
        dirs = [
            f"outputs/scans/{self.scan_id}/nmap",
            f"outputs/scans/{self.scan_id}/nuclei",
            f"outputs/scans/{self.scan_id}/zap",
            f"outputs/scans/{self.scan_id}/subdomains",
            f"outputs/scans/{self.scan_id}/directories",
            f"outputs/reports/{self.scan_id}"
        ]
        for dir in dirs:
            os.makedirs(dir, exist_ok=True)
    
    def run_subdomain_discovery(self):
        if "subfinder" in self.config['tools']['subdomain']['tools']:
            subfinder = SubfinderScanner(self.config, self.scan_id)
            subfinder.run_scan()
        
        if "amass" in self.config['tools']['subdomain']['tools']:
            amass = AmassScanner(self.config, self.scan_id)
            amass.run_scan()
    
    def run_directory_bruteforce(self, url):
        dirsearch = DirsearchScanner(self.config, self.scan_id)
        dirsearch.run_scan(url)
    
    def run_full_scan(self):
        # Subdomain discovery
        self.run_subdomain_discovery()
        
        # Process all targets
        for target in self.config['targets']:
            print(f"\n[*] Scanning target: {target}")
            
            # NMAP Scan
            nmap = NmapAutomator(self.config, self.scan_id)
            nmap_results = nmap.run_scan(target)
            
            # Nuclei Scan
            nuclei = NucleiAutomator(self.config, self.scan_id)
            nuclei_results = nuclei.run_scan(target, nmap_results)
            
            # ZAP Scan (if web ports found)
            zap_results = None
            if nmap_results.get('web_ports'):
                zap = ZAPAutomator(self.config, self.scan_id)
                zap_results = zap.run_scan(target, nmap_results)
                
                # Directory bruteforce for web services
                for port in nmap_results['web_ports']:
                    url = f"http://{target}:{port}" if port != 443 else f"https://{target}"
                    self.run_directory_bruteforce(url)
            
            # Generate report
            report = ReportEngine(self.config, self.scan_id)
            report.generate(target, nmap_results, nuclei_results, zap_results)
        
        # Send notification
        self.notifier.send("Scan Completed", f"Security scan {self.scan_id} finished")

if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run_full_scan()
