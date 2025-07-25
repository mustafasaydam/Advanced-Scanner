import subprocess
import json
import os
from datetime import datetime

class NucleiAutomator:
    def __init__(self, config, scan_id):
        self.config = config
        self.scan_id = scan_id
        self.output_dir = f"outputs/scans/{scan_id}/nuclei"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Auto-update templates if configured
        if config['tools']['nuclei']['auto_update']:
            self.update_templates()

    def update_templates(self):
        try:
            subprocess.run(["nuclei", "-update-templates"], check=True)
            print("[*] Updated Nuclei templates")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to update Nuclei templates: {e}")

    def run_scan(self, target, nmap_results=None):
        json_output = f"{self.output_dir}/{target.replace('.', '_')}_results.json"
        cmd = [
            "nuclei",
            "-target", target,
            "-severity", self.config['tools']['nuclei']['severity'],
            "-json",
            "-rate-limit", str(self.config['tools']['nuclei']['rate_limit']),
            "-timeout", str(self.config['tools']['nuclei']['timeout']),
            "-o", json_output
        ]
        
        # Add specific ports from NMAP results
        if nmap_results and nmap_results.get('web_ports'):
            cmd.extend(["-ports", ",".join(map(str, nmap_results['web_ports']))])
        
        # Add templates if specified
        if self.config['tools']['nuclei']['templates'] != "builtin":
            cmd.extend(["-t", self.config['tools']['nuclei']['templates']])
        
        try:
            print(f"[*] Running Nuclei scan on {target}")
            subprocess.run(cmd, check=True, timeout=3600)
            return self.parse_results(json_output)
        except Exception as e:
            print(f"[!] Nuclei scan failed: {e}")
            return []

    def parse_results(self, json_file):
        if not os.path.exists(json_file):
            return []
        
        with open(json_file, 'r') as f:
            lines = f.readlines()
        
        results = []
        for line in lines:
            try:
                result = json.loads(line)
                
                # Extract relevant information
                findings = {
                    'template': result.get('templateID'),
                    'name': result.get('info', {}).get('name'),
                    'severity': result.get('info', {}).get('severity'),
                    'description': result.get('info', {}).get('description'),
                    'reference': result.get('info', {}).get('reference'),
                    'type': result.get('type'),
                    'host': result.get('host'),
                    'matched': result.get('matched'),
                    'timestamp': datetime.now().isoformat(),
                    'curl_command': self.generate_curl_command(result)
                }
                
                # Add classification if available
                if result.get('info', {}).get('classification'):
                    findings.update(result['info']['classification'])
                
                results.append(findings)
            except json.JSONDecodeError:
                continue
        
        return results
    
    def generate_curl_command(self, result):
        """Generate curl command for HTTP findings"""
        if result.get('type') != 'http':
            return None
        
        host = result.get('host')
        matched = result.get('matched')
        
        if not host or not matched:
            return None
        
        return f"curl -XGET -H 'User-Agent: Mozilla/5.0' '{matched}'"
