import subprocess
import xml.etree.ElementTree as ET
import os
import json

class NmapScanner:
    def __init__(self, config, scan_id):
        self.config = config
        self.target = config['target']
        self.scan_id = scan_id
        self.output_dir = f"outputs/nmap/{scan_id}"
        os.makedirs(self.output_dir, exist_ok=True)

    def run_scan(self):
        # Build NMAP command
        xml_output = f"{self.output_dir}/scan.xml"
        json_output = f"{self.output_dir}/scan.json"
        cmd = [
            "nmap",
            *self.config['nmap']['options'].split(),
            *self.config['nmap']['timing'].split(),
            *self.config['nmap']['ports'].split(),
            "-oX", xml_output,
            "-oJ", json_output,
            self.target
        ]

        # Add custom scripts if any
        if os.path.exists(self.config['nmap']['custom_scripts']):
            cmd.extend(["--script", self.config['nmap']['custom_scripts'] + "*"])

        # Execute NMAP
        try:
            subprocess.run(cmd, check=True, timeout=3600)
        except subprocess.TimeoutExpired:
            print("[!] NMAP scan timed out")
        except subprocess.CalledProcessError as e:
            print(f"[!] NMAP scan failed: {e}")

        # Parse and return results
        return self.parse_results(xml_output)

    def parse_results(self, xml_file):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            results = {
                'host': self.target,
                'os': {},
                'ports': [],
                'web_ports': [],
                'vulnerabilities': [],
                'host_scripts': []
            }

            # Host and OS info
            host = root.find('host')
            if host is not None:
                # OS detection
                os_match = host.find('.//osmatch')
                if os_match is not None:
                    results['os'] = {
                        'name': os_match.get('name'),
                        'accuracy': os_match.get('accuracy'),
                        'osclass': [{
                            'type': oc.get('type'),
                            'vendor': oc.get('vendor'),
                            'osfamily': oc.get('osfamily'),
                            'osgen': oc.get('osgen'),
                            'accuracy': oc.get('accuracy')
                        } for oc in os_match.findall('.//osclass')]
                    }

                # Port information
                ports = host.findall('.//port')
                for port in ports:
                    port_data = {
                        'number': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': port.find('state').get('state') if port.find('state') is not None else 'unknown',
                        'service': port.find('service').get('name') if port.find('service') is not None else 'unknown',
                        'version': port.find('service').get('version') if port.find('service') is not None else 'unknown',
                        'product': port.find('service').get('product') if port.find('service') is not None else 'unknown'
                    }
                    results['ports'].append(port_data)

                    # Check for web services
                    if port_data['service'] in ['http', 'https', 'http-proxy', 'ssl', 'https-alt']:
                        results['web_ports'].append(port_data['number'])

                # Vulnerability scripts
                for script in host.findall('.//script'):
                    if script.get('id') == 'vulners':
                        for table in script.findall('.//table'):
                            vuln = {
                                'id': table.find('.//elem[@key="id"]').text,
                                'type': table.find('.//elem[@key="type"]').text,
                                'score': table.find('.//elem[@key="cvss"]').text,
                                'is_exploit': table.find('.//elem[@key="is_exploit"]').text,
                                'description': table.find('.//elem[@key="description"]').text
                            }
                            results['vulnerabilities'].append(vuln)

                # Host scripts output
                for script in host.findall('.//hostscript/script'):
                    script_data = {
                        'id': script.get('id'),
                        'output': script.get('output'),
                        'tables': []
                    }
                    for table in script.findall('.//table'):
                        table_data = {
                            'key': table.get('key'),
                            'elements': []
                        }
                        for elem in table.findall('.//elem'):
                            table_data['elements'].append({
                                'key': elem.get('key'),
                                'value': elem.text
                            })
                        script_data['tables'].append(table_data)
                    results['host_scripts'].append(script_data)

            return results

        except Exception as e:
            print(f"[!] Error parsing NMAP results: {e}")
            return None
