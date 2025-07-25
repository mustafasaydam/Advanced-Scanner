import schedule
import time
from datetime import datetime
from scripts.main import SecurityScanner
import yaml
import logging
import sys

class ScanScheduler:
    def __init__(self, config_path='config/config.yaml'):
        self.config_path = config_path
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_scanner.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def load_config(self):
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def run_scheduled_scan(self):
        """Run the security scan and handle exceptions"""
        logging.info("Starting scheduled security scan")
        try:
            config = self.load_config()
            scanner = SecurityScanner()
            scanner.run_full_scan()
            logging.info("Scheduled scan completed successfully")
        except Exception as e:
            logging.error(f"Scheduled scan failed: {str(e)}")
    
    def start(self):
        """Start the scheduler based on config"""
        config = self.load_config()
        
        if 'schedule' not in config:
            logging.error("No schedule configuration found")
            return
        
        schedule_config = config['schedule']
        
        if schedule_config.get('daily'):
            time = schedule_config['daily'].get('time', '00:00')
            schedule.every().day.at(time).do(self.run_scheduled_scan)
            logging.info(f"Scheduled daily scan at {time}")
        
        if schedule_config.get('hourly'):
            schedule.every().hour.do(self.run_scheduled_scan)
            logging.info("Scheduled hourly scans")
        
        if schedule_config.get('weekly'):
            day = schedule_config['weekly'].get('day', 'sunday')
            time = schedule_config['weekly'].get('time', '00:00')
            getattr(schedule.every(), day).at(time).do(self.run_scheduled_scan)
            logging.info(f"Scheduled weekly scan on {day} at {time}")
        
        logging.info("Scheduler started. Press Ctrl+C to exit.")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Scheduler stopped by user")
