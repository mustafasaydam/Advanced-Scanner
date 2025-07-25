import subprocess
import json
import os

class AmassScanner:
    def __init__(self, config, scan_id):
        self.config = config
        self.scan_id = scan_id
        self.output_dir = f"outputs/scans/{scan_id}/subdomains"
        os.makedirs(self.output_dir, exist_ok=True)

    def run_scan(self):
        output_file = f"{self.output_dir}/amass_results.json"
        cmd = [
            "amass", "enum",
            "-d", self.config['targets'][0],  # First target
            "-json", output_file,
            "-active",
            "-brute",
            "-timeout", "30"
        ]
        
        try:
            print("[*] Running Amass subdomain discovery")
            subprocess.run(cmd, check=True, timeout=1800)
            return self.parse_results(output_file)
        except Exception as e:
            print(f"[!] Amass scan failed: {e}")
            return []

    def parse_results(self, json_file):
        with open(json_file, 'r') as f:
            data = [json.loads(line) for line in f]
        
        return [{
            'subdomain': item['name'],
            'ip': item['addresses'][0]['ip'] if item['addresses'] else None,
            'source': item['sources'][0] if item['sources'] else None
        } for item in data]
