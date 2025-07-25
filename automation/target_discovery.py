import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from integrations.amass import AmassScanner
from integrations.subfinder import SubfinderScanner
import yaml
import os

class TargetDiscovery:
    def __init__(self, config):
        self.config = config
        self.active_targets = []
    
    def discover_subdomains(self):
        """Discover subdomains using multiple tools"""
        subdomains = set()
        
        if "amass" in self.config['tools']['subdomain']['tools']:
            amass = AmassScanner(self.config, "discovery")
            amass_results = amass.run_scan()
            subdomains.update([result['subdomain'] for result in amass_results])
        
        if "subfinder" in self.config['tools']['subdomain']['tools']:
            subfinder = SubfinderScanner(self.config, "discovery")
            subfinder_results = subfinder.run_scan()
            subdomains.update([result['subdomain'] for result in subfinder_results])
        
        return list(subdomains)
    
    def expand_ip_range(self, ip_range):
        """Convert CIDR notation to individual IPs"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(host) for host in network.hosts()]
        except ValueError:
            return [ip_range]
    
    def host_discovery(self, target):
        """Check if host is alive using ICMP ping"""
        try:
            if os.system(f"ping -c 1 -W 1 {target} > /dev/null 2>&1") == 0:
                return target
        except:
            return None
    
    def port_discovery(self, target, ports=[80, 443, 22, 3389]):
        """Check for open ports on target"""
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((target, port)) == 0:
                        open_ports.append(port)
            except:
                continue
        return open_ports
    
    def discover_targets(self):
        """Main discovery method that combines all techniques"""
        # Process all targets from config
        all_targets = []
        for target in self.config['targets']:
            if '/' in target:  # CIDR notation
                all_targets.extend(self.expand_ip_range(target))
            else:
                all_targets.append(target)
        
        # Discover subdomains
        if any(tool in self.config['tools']['subdomain']['tools'] for tool in ['amass', 'subfinder']):
            subdomains = self.discover_subdomains()
            all_targets.extend(subdomains)
        
        # Check which hosts are alive (parallel)
        with ThreadPoolExecutor(max_workers=20) as executor:
            alive_hosts = list(filter(None, executor.map(self.host_discovery, all_targets)))
        
        # Check for open ports (parallel)
        targets_with_ports = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(self.port_discovery, alive_hosts)
            for host, ports in zip(alive_hosts, results):
                if ports:
                    targets_with_ports[host] = ports
        
        self.active_targets = targets_with_ports
        return targets_with_ports
