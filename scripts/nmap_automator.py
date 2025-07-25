import subprocess
import xml.etree.ElementTree as ET
import json
import os
from datetime import datetime

class NmapAutomator:
    def __init__(self, config, scan_id):
        self.config = config
        self.scan_id = scan_id
        self.output_dir = f"outputs/scans/{scan_id}/nmap"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Auto-update Nmap scripts
        if config['tools']['nmap']['auto_update']:
            self.update_nmap_scripts()

    def update_nmap_scripts(self):
        try:
            subprocess.run(["nmap", "--script-updatedb"], check=True)
            print("[*] Updated Nmap script database")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to update Nmap scripts: {e}")

    def run_scan(self, target):
        # Dynamic profile-based scanning
        scan_profile = self.config['scan_profile']
        
        if scan_profile == "quick":
            cmd = self.build_quick_scan(target)
        elif scan_profile == "discovery":
            cmd = self.build_discovery_scan(target)
        else:  # full or standard
            cmd = self.build_full_scan(target)
        
        try:
            print(f"[*] Running NMAP scan ({scan_profile} profile) on {target}")
            subprocess.run(cmd, check=True, timeout=3600)
            return self.parse_results(target)
        except Exception as e:
            print(f"[!] NMAP scan failed: {e}")
            return None

    def build_quick_scan(self, target):
        xml_output = f"{self.output_dir}/{target}_quick.xml"
        return [
            "nmap", "-T4", "-F", "--open",
            "--script", "vulners,banner",
            "-oX", xml_output,
            target
        ]

    def build_discovery_scan(self, target):
        xml_output = f"{self.output_dir}/{target}_discovery.xml"
        return [
            "nmap", "-sn", "-PE", "-PP", "-PS21,22,23,25,80,443,3389",
            "-PA80,443", "-PU161", "-PY", "-g", "53",
            "-oX", xml_output,
            target
        ]

    def build_full_scan(self, target):
        xml_output = f"{self.output_dir}/{target}_full.xml"
        json_output = f"{self.output_dir}/{target}_full.json"
        
        cmd = [
            "nmap",
            *self.config['tools']['nmap']['options'].split(),
            *self.config['tools']['nmap']['timing'].split(),
            *self.config['tools']['nmap']['ports'].split(),
            "--script", "vulners,http-enum,http-title,ssl-enum-ciphers",
            "-oX", xml_output,
            "-oJ", json_output,
            target
        ]
        
        if self.config['scan_profile'] == "full":
            cmd.extend(["-A", "--script", "default,safe,vuln"])
        
        return cmd

    def parse_results(self, target):
        xml_file = f"{self.output_dir}/{target}_{self.config['scan_profile']}.xml"
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # ... (previous parsing logic with enhancements)
            
            # Add service detection for common vulnerabilities
            for port in results['ports']:
                if port['service'] == 'http':
                    port['checks'] = ['web-app', 'xss', 'injection']
                elif port['service'] == 'ssh':
                    port['checks'] = ['auth', 'bruteforce']
                elif port['service'] == 'smb':
                    port['checks'] = ['eternalblue', 'smbghost']
            
            return results
            
        except Exception as e:
            print(f"[!] Error parsing NMAP results: {e}")
            return None
