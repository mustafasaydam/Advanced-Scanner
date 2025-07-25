from jinja2 import Environment, FileSystemLoader
import pdfkit
import json
import os
from datetime import datetime
import webbrowser

class ReportEngine:
    def __init__(self, config, scan_id):
        self.config = config
        self.scan_id = scan_id
        self.output_dir = f"outputs/reports/{scan_id}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Setup Jinja2 environment
        self.env = Environment(loader=FileSystemLoader('templates'))
    
    def generate(self, target, nmap_results, nuclei_results, zap_results):
        """Generate all report formats"""
        report_data = self.prepare_data(target, nmap_results, nuclei_results, zap_results)
        
        # Save raw data
        with open(f"{self.output_dir}/{target}_report_data.json", 'w') as f:
            json.dump(report_data, f, indent=4)
        
        # Generate HTML report
        self.generate_html(report_data, target)
        
        # Generate PDF if configured
        if 'pdf' in self.config['output_formats']:
            self.generate_pdf(report_data, target)
        
        # Open report in browser
        if self.config.get('auto_open', True):
            webbrowser.open(f"file://{os.path.abspath(self.output_dir)}/{target}_report.html")
    
    def prepare_data(self, target, nmap_results, nuclei_results, zap_results):
        """Prepare consolidated report data"""
        return {
            'meta': {
                'scan_id': self.scan_id,
                'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target': target,
                'scan_profile': self.config['scan_profile']
            },
            'nmap': nmap_results,
            'nuclei': nuclei_results,
            'zap': zap_results,
            'stats': self.calculate_stats(nmap_results, nuclei_results, zap_results),
            'recommendations': self.generate_recommendations(nmap_results, nuclei_results, zap_results)
        }
    
    def calculate_stats(self, nmap, nuclei, zap):
        """Calculate summary statistics"""
        stats = {
            'open_ports': len(nmap['ports']) if nmap else 0,
            'services': len(set(p['service'] for p in nmap['ports'])) if nmap else 0,
            'nmap_vulns': len(nmap['vulnerabilities']) if nmap and 'vulnerabilities' in nmap else 0,
            'nuclei_findings': len(nuclei) if nuclei else 0,
            'critical_findings': len([n for n in nuclei if n['severity'] == 'critical']) if nuclei else 0,
            'zap_alerts': zap['total_alerts'] if zap else 0,
            'high_risk_alerts': zap['high_risk'] if zap else 0
        }
        
        stats['total_risks'] = (
            stats['nmap_vulns'] + 
            stats['nuclei_findings'] + 
            stats['zap_alerts']
        )
        
        return stats
    
    def generate_recommendations(self, nmap, nuclei, zap):
        """Generate actionable recommendations"""
        recs = []
        
        # NMAP recommendations
        if nmap and 'ports' in nmap:
            for port in nmap['ports']:
                if port['service'] == 'http' and port.get('version'):
                    recs.append({
                        'type': 'upgrade',
                        'severity': 'high',
                        'description': f"Upgrade {port['service']} version {port['version']}",
                        'action': 'Update web server to latest stable version'
                    })
        
        # Nuclei recommendations
        if nuclei:
            for finding in nuclei:
                if finding['severity'] in ['high', 'critical']:
                    recs.append({
                        'type': 'vulnerability',
                        'severity': finding['severity'],
                        'description': finding['description'],
                        'action': finding.get('solution', 'Apply security patches')
                    })
        
        # ZAP recommendations
        if zap and 'alerts' in zap:
            for alert in zap['alerts']:
                if alert['risk'] in ['High', 'Medium']:
                    recs.append({
                        'type': 'web',
                        'severity': alert['risk'].lower(),
                        'description': alert['description'],
                        'action': alert['solution']
                    })
        
        return recs
    
    def generate_html(self, data, target):
        """Generate HTML report"""
        template = self.env.get_template('report_template.html')
        html = template.render(data=data)
        
        output_file = f"{self.output_dir}/{target}_report.html"
        with open(output_file, 'w') as f:
            f.write(html)
    
    def generate_pdf(self, data, target):
        """Generate PDF report"""
        try:
            html_file = f"{self.output_dir}/{target}_report.html"
            pdf_file = f"{self.output_dir}/{target}_report.pdf"
            
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'quiet': ''
            }
            
            pdfkit.from_file(html_file, pdf_file, options=options)
        except Exception as e:
            print(f"[!] PDF generation failed: {e}")
