import subprocess
import os
import xml.etree.ElementTree as ET

class DirsearchScanner:
    def __init__(self, config, scan_id):
        self.config = config
        self.scan_id = scan_id
        self.output_dir = f"outputs/scans/{scan_id}/directories"
        os.makedirs(self.output_dir, exist_ok=True)

    def run_scan(self, url):
        report_file = f"{self.output_dir}/{url.replace('://', '_').replace('/', '_')}.xml"
        cmd = [
            "dirsearch",
            "-u", url,
            "-e", "php,asp,aspx,jsp,html,js",
            "-x", "403,404",
            "--format", "xml",
            "--output", report_file,
            "--random-agents",
            "--max-time", "300"
        ]
        
        try:
            print(f"[*] Running directory bruteforce on {url}")
            subprocess.run(cmd, check=True, timeout=1800)
            return self.parse_results(report_file)
        except Exception as e:
            print(f"[!] Dirsearch scan failed: {e}")
            return []

    def parse_results(self, xml_file):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            return [{
                'url': item.find('url').text,
                'status': item.find('status').text,
                'content_length': item.find('contentLength').text,
                'redirect': item.find('redirect').text if item.find('redirect') is not None else None
            } for item in root.findall('.//item')]
        
        except Exception as e:
            print(f"[!] Error parsing Dirsearch results: {e}")
            return []
