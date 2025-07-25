import subprocess
import json
import os
from datetime import datetime

class SubfinderScanner:
    def __init__(self, config, scan_id):
        self.config = config
        self.scan_id = scan_id
        self.output_dir = f"outputs/scans/{scan_id}/subdomains"
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_scan(self):
        output_file = f"{self.output_dir}/subfinder_results.json"
        cmd = [
            "subfinder",
            "-d", self.config['targets'][0],
            "-o", output_file,
            "-oJ",
            "-silent",
            "-t", "10",
            "-timeout", "30"
        ]
        
        try:
            print("[*] Running Subfinder subdomain discovery")
            subprocess.run(cmd, check=True, timeout=1800)
            return self.parse_results(output_file)
        except Exception as e:
            print(f"[!] Subfinder scan failed: {e}")
            return []
    
    def parse_results(self, json_file):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            return [{
                'subdomain': item['host'],
                'ip': item.get('ip', ''),
                'source': item.get('source', '')
            } for item in data]
        except Exception as e:
            print(f"[!] Error parsing Subfinder results: {e}")
            return []
