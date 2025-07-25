import time
from zapv2 import ZAPv2
import json
import os
from datetime import datetime

class ZAPAutomator:
    def __init__(self, config, scan_id):
        self.config = config
        self.scan_id = scan_id
        self.output_dir = f"outputs/scans/{scan_id}/zap"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize ZAP API client
        self.zap = ZAPv2(
            apikey=config['tools']['zap']['api_key'],
            proxies={'http': config['tools']['zap']['proxy'], 
                    'https': config['tools']['zap']['proxy']}
        )
        
        # Configure ZAP settings
        self.configure_zap()

    def configure_zap(self):
        """Set up ZAP with custom configurations"""
        # Set scan policy
        self.zap.ascan.set_scan_policy(
            scanpolicyname=self.config['tools']['zap']['policy']
        )
        
        # Enable all passive scanners
        self.zap.pscan.enable_all_scanners()
        
        # Set alert threshold to Medium
        self.zap.ascan.set_alert_threshold(threshold='Medium')
        
        # Set max scan duration
        self.zap.ascan.set_option_max_scan_duration_in_mins(
            self.config['tools']['zap']['max_scan_duration']
        )

    def run_scan(self, target, nmap_results):
        """Run full ZAP scan including spider and active scan"""
        results = {
            'target': target,
            'spider': {},
            'ajax_spider': {},
            'active_scan': {},
            'alerts': [],
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Start traditional spider
            print("[*] Starting ZAP spider...")
            scan_id = self.zap.spider.scan(target)
            time.sleep(2)
            
            # Monitor spider progress
            while int(self.zap.spider.status(scan_id)) < 100:
                time.sleep(5)
            
            results['spider'] = {
                'status': 'completed',
                'urls_found': self.zap.spider.results(scan_id),
                'scan_id': scan_id
            }

            # Run AJAX spider if enabled
            if self.config['tools']['zap'].get('ajax_spider', True):
                print("[*] Starting AJAX spider...")
                self.zap.ajaxSpider.scan(target)
                
                while self.zap.ajaxSpider.status == 'running':
                    time.sleep(5)
                
                results['ajax_spider'] = {
                    'status': self.zap.ajaxSpider.status,
                    'urls_found': self.zap.ajaxSpider.results
                }

            # Run active scan
            print("[*] Starting active scan...")
            scan_id = self.zap.ascan.scan(
                target, 
                recurse=True, 
                scanpolicyname=self.config['tools']['zap']['policy']
            )
            
            # Monitor active scan progress
            while int(self.zap.ascan.status(scan_id)) < 100:
                time.sleep(10)
            
            results['active_scan'] = {
                'status': 'completed',
                'scan_id': scan_id,
                'progress': self.zap.ascan.status(scan_id)
            }

            # Get all alerts
            alerts = self.zap.core.alerts()
            results['alerts'] = alerts

            # Save full report
            self.save_results(results)
            
            return self.parse_results(results)

        except Exception as e:
            print(f"[!] ZAP scan failed: {e}")
            results['error'] = str(e)
            self.save_results(results)
            return None

    def save_results(self, results):
        """Save raw results to JSON file"""
        output_file = f"{self.output_dir}/{results['target'].replace('.', '_')}_full.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)

    def parse_results(self, results):
        """Parse and format ZAP results for reporting"""
        parsed_alerts = []
        
        for alert in results.get('alerts', []):
            parsed_alert = {
                'name': alert.get('name'),
                'risk': alert.get('risk'),
                'confidence': alert.get('confidence'),
                'description': alert.get('description'),
                'solution': alert.get('solution'),
                'reference': alert.get('reference'),
                'cwe': alert.get('cweid'),
                'wasc': alert.get('wascid'),
                'url': alert.get('url'),
                'param': alert.get('param'),
                'attack': alert.get('attack'),
                'evidence': alert.get('evidence'),
                'alert_ref': alert.get('alertRef')
            }
            parsed_alerts.append(parsed_alert)
        
        return {
            'target': results['target'],
            'alerts': parsed_alerts,
            'total_alerts': len(parsed_alerts),
            'high_risk': len([a for a in parsed_alerts if a['risk'] == 'High']),
            'medium_risk': len([a for a in parsed_alerts if a['risk'] == 'Medium']),
            'low_risk': len([a for a in parsed_alerts if a['risk'] == 'Low']),
            'spider_urls': len(results.get('spider', {}).get('urls_found', [])),
            'ajax_urls': len(results.get('ajax_spider', {}).get('urls_found', []))
        }
