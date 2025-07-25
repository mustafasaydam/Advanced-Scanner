#!/usr/bin/env python3
import os
import sys
import json
import time
import argparse
import subprocess
from xml.etree import ElementTree as ET
from zapv2 import ZAPv2
import pandas as pd

# ANSI renk kodları
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_END = "\033[0m"

def print_banner():
    banner = f"""
{COLOR_BLUE}
  ███╗   ███╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ████╗ ████║██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██╔████╔██║███████╗██║     ███████║██╔██╗ ██║
  ██║╚██╔╝██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██║ ╚═╝ ██║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{COLOR_END}
{COLOR_YELLOW}      Gelişmiş Güvenlik Tarama Aracı{COLOR_END}
    """
    print(banner)

def run_command(cmd, timeout=600):
    try:
        result = subprocess.run(cmd, shell=True, check=True, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE,
                              timeout=timeout)
        return result.stdout.decode('utf-8'), result.stderr.decode('utf-8'), None
    except subprocess.CalledProcessError as e:
        return e.stdout.decode('utf-8'), e.stderr.decode('utf-8'), e
    except subprocess.TimeoutExpired:
        return "", "", "Timeout expired"

def nmap_scan(target, scan_type="full"):
    print(f"{COLOR_BLUE}[*] Nmap taraması başlatılıyor ({scan_type})...{COLOR_END}")
    
    output_files = []
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    
    # Hızlı tarama (ilk 1000 port)
    if scan_type in ["quick", "full"]:
        output_file = f"nmap_quick_{timestamp}.xml"
        cmd = f"nmap -T4 -F {target} -oX {output_file}"
        print(f"{COLOR_YELLOW}[*] Hızlı port taraması yapılıyor...{COLOR_END}")
        run_command(cmd)
        output_files.append(output_file)
    
    # Detaylı tarama (tüm portlar ve servis bilgisi)
    if scan_type in ["full", "detailed"]:
        output_file = f"nmap_detailed_{timestamp}.xml"
        cmd = f"nmap -T4 -A -sV -p- {target} -oX {output_file}"
        print(f"{COLOR_YELLOW}[*] Detaylı servis taraması yapılıyor...{COLOR_END}")
        run_command(cmd)
        output_files.append(output_file)
    
    # Güvenlik açığı taraması
    if scan_type == "full":
        output_file = f"nmap_vuln_{timestamp}.xml"
        cmd = f"nmap --script vuln {target} -oX {output_file}"
        print(f"{COLOR_YELLOW}[*] Güvenlik açığı taraması yapılıyor...{COLOR_END}")
        run_command(cmd)
        output_files.append(output_file)
    
    # Sonuçları birleştirme
    if len(output_files) > 1:
        final_output = f"nmap_final_{timestamp}.xml"
        merge_nmap_results(output_files, final_output)
        print(f"{COLOR_GREEN}[+] Nmap taraması tamamlandı. Sonuçlar: {final_output}{COLOR_END}")
        return final_output
    else:
        print(f"{COLOR_GREEN}[+] Nmap taraması tamamlandı. Sonuçlar: {output_files[0]}{COLOR_END}")
        return output_files[0]

def merge_nmap_results(input_files, output_file):
    """Nmap XML sonuçlarını birleştir"""
    main_tree = None
    
    for file in input_files:
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            
            if main_tree is None:
                main_tree = tree
                main_root = root
                continue
            
            # Host bilgilerini birleştir
            for host in root.findall('host'):
                main_root.append(host)
                
        except ET.ParseError as e:
            print(f"{COLOR_RED}[-] Hata: {file} işlenirken XML parse hatası: {e}{COLOR_END}")
    
    if main_tree is not None:
        main_tree.write(output_file)

def nuclei_scan(target, template_path="~/nuclei-templates"):
    print(f"{COLOR_BLUE}[*] Nuclei ile güvenlik açığı taraması başlatılıyor...{COLOR_END}")
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_file = f"nuclei_results_{timestamp}.json"
    
    cmd = f"nuclei -u {target} -t {template_path} -json -o {output_file}"
    stdout, stderr, error = run_command(cmd, timeout=1200)
    
    if error:
        print(f"{COLOR_RED}[-] Nuclei taramasında hata: {stderr}{COLOR_END}")
        return None
    
    print(f"{COLOR_GREEN}[+] Nuclei taraması tamamlandı. Sonuçlar: {output_file}{COLOR_END}")
    return output_file

def zap_scan(target, api_key='your-api-key'):
    print(f"{COLOR_BLUE}[*] OWASP ZAP taraması başlatılıyor...{COLOR_END}")
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_file = f"zap_report_{timestamp}.html"
    
    try:
        # ZAP'ı başlat
        zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
        print(f"{COLOR_YELLOW}[*] Hedef tarama başlatılıyor: {target}{COLOR_END}")
        zap.urlopen(target)
        time.sleep(2)
        
        # Aktif tarama
        print(f"{COLOR_YELLOW}[*] Aktif tarama başlatılıyor...{COLOR_END}")
        scan_id = zap.ascan.scan(target)
        
        # Tarama ilerlemesini kontrol et
        while int(zap.ascan.status(scan_id)) < 100:
            status = zap.ascan.status(scan_id)
            print(f"{COLOR_YELLOW}[*] Tarama devam ediyor: %{status}{COLOR_END}")
            time.sleep(10)
        
        # Rapor oluştur
        print(f"{COLOR_YELLOW}[*] Rapor oluşturuluyor...{COLOR_END}")
        with open(output_file, 'w') as f:
            f.write(zap.core.htmlreport())
        
        print(f"{COLOR_GREEN}[+] ZAP taraması tamamlandı. Sonuçlar: {output_file}{COLOR_END}")
        return output_file
    
    except Exception as e:
        print(f"{COLOR_RED}[-] ZAP taramasında hata: {str(e)}{COLOR_END}")
        return None

def subdomain_scan(target):
    print(f"{COLOR_BLUE}[*] Subdomain keşfi başlatılıyor...{COLOR_END}")
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_file = f"subdomains_{timestamp}.txt"
    
    # Amass kullanarak subdomain bulma
    print(f"{COLOR_YELLOW}[*] Amass ile subdomain taraması...{COLOR_END}")
    cmd = f"amass enum -d {target} -o {output_file}"
    run_command(cmd)
    
    # Sublist3r ile doğrulama
    print(f"{COLOR_YELLOW}[*] Sublist3r ile doğrulama...{COLOR_END}")
    cmd = f"sublist3r -d {target} -o sublist3r_{timestamp}.txt"
    run_command(cmd)
    
    # Sonuçları birleştir ve tekilleştir
    with open(output_file, 'a') as main_file:
        with open(f"sublist3r_{timestamp}.txt", 'r') as sl_file:
            subdomains = set(sl_file.readlines())
            main_file.writelines(subdomains)
    
    print(f"{COLOR_GREEN}[+] Subdomain keşfi tamamlandı. Sonuçlar: {output_file}{COLOR_END}")
    return output_file

def generate_report(nmap_file, nuclei_file, zap_file, subdomain_file=None):
    print(f"{COLOR_BLUE}[*] Konsolide rapor oluşturuluyor...{COLOR_END}")
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_file = f"security_report_{timestamp}.xlsx"
    
    # Verileri topla
    report_data = {
        'Scan Information': {
            'Date': timestamp,
            'Tools Used': 'Nmap, Nuclei, OWASP ZAP' + (', Subdomain scanners' if subdomain_file else '')
        }
    }
    
    # Nmap sonuçlarını işle
    if nmap_file and os.path.exists(nmap_file):
        nmap_data = parse_nmap_results(nmap_file)
        report_data['Network Scan'] = nmap_data
    
    # Nuclei sonuçlarını işle
    if nuclei_file and os.path.exists(nuclei_file):
        with open(nuclei_file, 'r') as f:
            nuclei_results = [json.loads(line) for line in f.readlines()]
        report_data['Web Vulnerabilities'] = nuclei_results
    
    # Subdomain sonuçları
    if subdomain_file and os.path.exists(subdomain_file):
        with open(subdomain_file, 'r') as f:
            subdomains = f.readlines()
        report_data['Subdomains'] = {'count': len(subdomains), 'domains': subdomains}
    
    # Excel raporu oluştur
    with pd.ExcelWriter(output_file) as writer:
        for sheet_name, data in report_data.items():
            if isinstance(data, dict):
                df = pd.DataFrame.from_dict(data, orient='index')
                df.to_excel(writer, sheet_name=sheet_name)
            elif isinstance(data, list):
                df = pd.DataFrame(data)
                df.to_excel(writer, sheet_name=sheet_name)
    
    print(f"{COLOR_GREEN}[+] Rapor oluşturuldu: {output_file}{COLOR_END}")
    return output_file

def parse_nmap_results(xml_file):
    """Nmap XML sonuçlarını parse eder"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        results = {
            'scan_info': {},
            'hosts': []
        }
        
        # Scan bilgileri
        scan_info = root.find('scaninfo')
        if scan_info is not None:
            results['scan_info'] = scan_info.attrib
        
        # Host bilgileri
        for host in root.findall('host'):
            host_data = {
                'address': None,
                'ports': [],
                'os': None
            }
            
            # Adres bilgisi
            address = host.find('address')
            if address is not None:
                host_data['address'] = address.attrib
            
            # Port bilgileri
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_data = port.attrib
                    service = port.find('service')
                    if service is not None:
                        port_data['service'] = service.attrib
                    host_data['ports'].append(port_data)
            
            # OS bilgisi
            os = host.find('os')
            if os is not None:
                os_match = os.find('osmatch')
                if os_match is not None:
                    host_data['os'] = os_match.attrib
            
            results['hosts'].append(host_data)
        
        return results
    
    except ET.ParseError as e:
        print(f"{COLOR_RED}[-] Nmap sonuçları parse edilemedi: {e}{COLOR_END}")
        return {}

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='SecAutoScan - Entegre Güvenlik Tarama Aracı')
    parser.add_argument('-t', '--target', required=True, help='Taranacak hedef (URL veya IP)')
    parser.add_argument('-m', '--mode', choices=['full', 'web', 'network', 'subdomain'], 
                       default='full', help='Tarama modu (default: full)')
    parser.add_argument('-o', '--output', help='Çıktı dosyası adı')
    parser.add_argument('--zap-api', default='your-api-key', help='OWASP ZAP API anahtarı')
    parser.add_argument('--nuclei-templates', default='~/nuclei-templates', 
                       help='Nuclei template dizini')
    
    args = parser.parse_args()
    
    # Çıktı dizini oluştur
    if not os.path.exists('reports'):
        os.makedirs('reports')
    
    # Taramaları başlat
    nmap_results = None
    nuclei_results = None
    zap_results = None
    subdomain_results = None
    
    if args.mode in ['full', 'network']:
        nmap_results = nmap_scan(args.target, 'full' if args.mode == 'full' else 'detailed')
    
    if args.mode in ['full', 'web']:
        nuclei_results = nuclei_scan(args.target, args.nuclei_templates)
        zap_results = zap_scan(args.target, args.zap_api)
    
    if args.mode in ['full', 'subdomain']:
        if 'http' in args.target:
            domain = args.target.split('//')[1].split('/')[0]
        else:
            domain = args.target
        subdomain_results = subdomain_scan(domain)
    
    # Rapor oluştur
    report_file = generate_report(
        nmap_results, 
        nuclei_results, 
        zap_results, 
        subdomain_results
    )
    
    print(f"{COLOR_GREEN}\n[+] Tüm taramalar başarıyla tamamlandı!{COLOR_END}")
    print(f"{COLOR_GREEN}[+] Final rapor: {report_file}{COLOR_END}")

if __name__ == "__main__":
    main()
