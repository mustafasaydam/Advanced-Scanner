#!/usr/bin/env python3
import os
import sys
import json
import time
import argparse
import subprocess
from xml.etree import ElementTree as ET
import pandas as pd
from xml.dom import minidom
import ipaddress
import socket

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

def prettify_xml(xml_string):
    """Return pretty-printed XML as a string"""
    parsed = minidom.parseString(xml_string)
    return parsed.toprettyxml(indent="  ")

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

def nmap_scan(ip_target, scan_type="full"):
    """Sadece IP hedefleri için Nmap taraması yapar"""
    if not is_ip_target(ip_target):
        print(f"{COLOR_RED}[-] Hata: Nmap taraması sadece IP adresleri/blokları için çalışır{COLOR_END}")
        return None, None

    print(f"{COLOR_BLUE}[*] Nmap taraması başlatılıyor ({scan_type})...{COLOR_END}")
    
    output_files = []
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    
    # Hızlı tarama (ilk 1000 port)
    if scan_type in ["quick", "full"]:
        output_file = f"reports/nmap_quick_{timestamp}.xml"
        pretty_file = f"reports/nmap_quick_{timestamp}_pretty.xml"
        cmd = f"nmap -T4 -F {ip_target} -oX {output_file}"
        print(f"{COLOR_YELLOW}[*] Hızlı port taraması yapılıyor...{COLOR_END}")
        run_command(cmd)
        
        with open(output_file, 'r') as f:
            pretty_xml = prettify_xml(f.read())
        with open(pretty_file, 'w') as f:
            f.write(pretty_xml)
        output_files.append(pretty_file)
    
    # Detaylı tarama (tüm portlar ve servis bilgisi)
    if scan_type in ["full", "detailed"]:
        output_file = f"reports/nmap_detailed_{timestamp}.xml"
        pretty_file = f"reports/nmap_detailed_{timestamp}_pretty.xml"
        cmd = f"nmap -T4 -A -sV -p- {ip_target} -oX {output_file}"
        print(f"{COLOR_YELLOW}[*] Detaylı servis taraması yapılıyor...{COLOR_END}")
        run_command(cmd)
        
        with open(output_file, 'r') as f:
            pretty_xml = prettify_xml(f.read())
        with open(pretty_file, 'w') as f:
            f.write(pretty_xml)
        output_files.append(pretty_file)
    
    # Güvenlik açığı taraması
    if scan_type == "full":
        output_file = f"reports/nmap_vuln_{timestamp}.xml"
        pretty_file = f"reports/nmap_vuln_{timestamp}_pretty.xml"
        cmd = f"nmap --script vuln {ip_target} -oX {output_file}"
        print(f"{COLOR_YELLOW}[*] Güvenlik açığı taraması yapılıyor...{COLOR_END}")
        run_command(cmd)
        
        with open(output_file, 'r') as f:
            pretty_xml = prettify_xml(f.read())
        with open(pretty_file, 'w') as f:
            f.write(pretty_xml)
        output_files.append(pretty_file)
    
    # HTML rapor oluştur
    html_file = f"reports/nmap_report_{timestamp}.html"
    cmd = f"xsltproc {output_files[-1]} -o {html_file}"
    run_command(cmd)
    
    # Sonuçları birleştir
    if len(output_files) > 1:
        final_output = f"reports/nmap_final_{timestamp}.xml"
        pretty_final = f"reports/nmap_final_{timestamp}_pretty.xml"
        merge_nmap_results(output_files, final_output)
        
        with open(final_output, 'r') as f:
            pretty_xml = prettify_xml(f.read())
        with open(pretty_final, 'w') as f:
            f.write(pretty_xml)
        
        print(f"{COLOR_GREEN}[+] Nmap taraması tamamlandı. Sonuçlar:{COLOR_END}")
        print(f"  - XML Rapor: {pretty_final}")
        print(f"  - HTML Rapor: {html_file}")
        return pretty_final, html_file
    else:
        print(f"{COLOR_GREEN}[+] Nmap taraması tamamlandı. Sonuçlar:{COLOR_END}")
        print(f"  - XML Rapor: {output_files[0]}")
        print(f"  - HTML Rapor: {html_file}")
        return output_files[0], html_file

def nuclei_scan(url_target, template_path="~/.local/nuclei-templates"):
    """URL hedefleri için Nuclei taraması yapar"""
    if is_ip_target(url_target):
        print(f"{COLOR_RED}[-] Hata: Nuclei taraması URL'ler için çalışır{COLOR_END}")
        return None, None

    print(f"{COLOR_BLUE}[*] Nuclei ile güvenlik açığı taraması başlatılıyor...{COLOR_END}")
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    json_file = f"reports/nuclei_results_{url_target.replace('/', '_')}_{timestamp}.json"
    html_file = f"reports/nuclei_report_{url_target.replace('/', '_')}_{timestamp}.html"
    
    # Template path'i düzelt
    template_path = os.path.expanduser(template_path)
    
    # Nuclei komutu (güncel sürümler için)
    cmd = f"nuclei -u {url_target} -t {template_path} -j -o {json_file}"
    stdout, stderr, error = run_command(cmd, timeout=1200)
    
    if error:
        print(f"{COLOR_RED}[-] Nuclei taramasında hata: {stderr}{COLOR_END}")
        return None, None
    
    # HTML rapor oluştur
    try:
        with open(json_file, 'r') as f:
            vulnerabilities = [json.loads(line) for line in f.readlines()]
        
        html_content = generate_nuclei_html(url_target, vulnerabilities, timestamp)
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        print(f"{COLOR_GREEN}[+] Nuclei taraması tamamlandı. Sonuçlar:{COLOR_END}")
        print(f"  - JSON Rapor: {json_file}")
        print(f"  - HTML Rapor: {html_file}")
        return json_file, html_file
    
    except Exception as e:
        print(f"{COLOR_RED}[-] Nuclei raporu oluşturulurken hata: {str(e)}{COLOR_END}")
        return json_file, None

def run_zap_scan(target_url):
    """Terminal komutuyla basit ZAP taraması yapar"""
    print(f"{COLOR_BLUE}[*] ZAP taraması başlatılıyor: {target_url}{COLOR_END}")
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_file = f"reports/zap_report_{target_url.replace('://', '_').replace('/', '_')}_{timestamp}.html"
    
    cmd = f"zap.sh -cmd -quickurl {target_url} -quickout {report_file}"
    stdout, stderr, error = run_command(cmd, timeout=1800)
    
    if error:
        print(f"{COLOR_RED}[-] ZAP taramasında hata: {stderr}{COLOR_END}")
        return None
    
    print(f"{COLOR_GREEN}[+] ZAP taraması tamamlandı. Rapor: {report_file}{COLOR_END}")
    return report_file

def subdomain_scan(domain_target):
    """Domain hedefleri için subdomain keşfi yapar"""
    if is_ip_target(domain_target):
        print(f"{COLOR_RED}[-] Hata: Subdomain taraması sadece domainler için çalışır{COLOR_END}")
        return None, None

    print(f"{COLOR_BLUE}[*] Subdomain keşfi başlatılıyor...{COLOR_END}")
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_file = f"reports/subdomains_{domain_target}_{timestamp}.txt"
    html_file = f"reports/subdomains_{domain_target}_{timestamp}.html"
    
    # Amass ile tarama
    print(f"{COLOR_YELLOW}[*] Amass ile subdomain taraması...{COLOR_END}")
    cmd = f"amass enum -d {domain_target} -o {output_file}"
    run_command(cmd)
    
    # Sublist3r ile doğrulama
    print(f"{COLOR_YELLOW}[*] Sublist3r ile doğrulama...{COLOR_END}")
    sl_file = f"reports/sublist3r_{domain_target}_{timestamp}.txt"
    cmd = f"sublist3r -d {domain_target} -o {sl_file}"
    run_command(cmd)
    
    # Sonuçları birleştir ve tekilleştir
    if os.path.exists(sl_file):
        with open(output_file, 'a') as main_file:
            with open(sl_file, 'r') as sl_file:
                subdomains = set(line.strip() for line in sl_file if line.strip())
                main_file.writelines(f"{sub}\n" for sub in subdomains)
    
    # HTML rapor oluştur
    with open(html_file, 'w') as f:
        f.write(generate_subdomain_html(domain_target, output_file, timestamp))
    
    print(f"{COLOR_GREEN}[+] Subdomain keşfi tamamlandı. Sonuçlar:{COLOR_END}")
    print(f"  - Metin Raporu: {output_file}")
    print(f"  - HTML Raporu: {html_file}")
    return output_file, html_file

def is_ip_target(target):
    """Hedefin IP adresi/bloğu olup olmadığını kontrol eder"""
    try:
        if '/' in target:
            ipaddress.ip_network(target)
            return True
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def generate_nuclei_html(target, vulnerabilities, timestamp):
    """Nuclei sonuçları için HTML rapor oluşturur"""
    return f"""
<html>
<head>
    <title>Nuclei Tarama Raporu - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .vuln {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
        .critical {{ background-color: #ffdddd; border-left: 5px solid #f44336; }}
        .high {{ background-color: #ffebee; border-left: 5px solid #ff5252; }}
        .medium {{ background-color: #fff8e1; border-left: 5px solid #ffc107; }}
        .low {{ background-color: #e8f5e9; border-left: 5px solid #4caf50; }}
        .info {{ background-color: #e3f2fd; border-left: 5px solid #2196f3; }}
        .severity {{ font-weight: bold; padding: 3px 8px; border-radius: 3px; color: white; }}
        .severity-critical {{ background-color: #f44336; }}
        .severity-high {{ background-color: #ff5252; }}
        .severity-medium {{ background-color: #ffc107; }}
        .severity-low {{ background-color: #4caf50; }}
        .severity-info {{ background-color: #2196f3; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>Nuclei Güvenlik Açığı Raporu</h1>
    <p>Oluşturulma Tarihi: {timestamp}</p>
    <p>Hedef: {target}</p>
    <h2>Özet</h2>
    <table>
        <tr>
            <th>Önem Derecesi</th>
            <th>Sayı</th>
        </tr>
        <tr>
            <td><span class="severity severity-critical">KRİTİK</span></td>
            <td>{len([v for v in vulnerabilities if v.get('info', {}).get('severity', '').lower() == 'critical'])}</td>
        </tr>
        <tr>
            <td><span class="severity severity-high">YÜKSEK</span></td>
            <td>{len([v for v in vulnerabilities if v.get('info', {}).get('severity', '').lower() == 'high'])}</td>
        </tr>
        <tr>
            <td><span class="severity severity-medium">ORTA</span></td>
            <td>{len([v for v in vulnerabilities if v.get('info', {}).get('severity', '').lower() == 'medium'])}</td>
        </tr>
        <tr>
            <td><span class="severity severity-low">DÜŞÜK</span></td>
            <td>{len([v for v in vulnerabilities if v.get('info', {}).get('severity', '').lower() == 'low'])}</td>
        </tr>
        <tr>
            <td><span class="severity severity-info">BİLGİ</span></td>
            <td>{len([v for v in vulnerabilities if v.get('info', {}).get('severity', '').lower() == 'info'])}</td>
        </tr>
        <tr>
            <td><strong>Toplam</strong></td>
            <td><strong>{len(vulnerabilities)}</strong></td>
        </tr>
    </table>
    <h2>Güvenlik Açıkları</h2>
    {"".join(format_vulnerability(v) for v in vulnerabilities)}
</body>
</html>
    """

def generate_subdomain_html(domain, subdomain_file, timestamp):
    """Subdomain sonuçları için HTML rapor oluşturur"""
    with open(subdomain_file, 'r') as f:
        subdomains = [line.strip() for line in f.readlines() if line.strip()]
    
    return f"""
<html>
<head>
    <title>Subdomain Keşif Raporu - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>Subdomain Keşif Raporu</h1>
    <p>Oluşturulma Tarihi: {timestamp}</p>
    <p>Hedef Domain: {domain}</p>
    <h2>Bulunan Subdomainler ({len(subdomains)})</h2>
    <table>
        <tr><th>#</th><th>Subdomain</th></tr>
        {"".join(f'<tr><td>{i+1}</td><td>{sub}</td></tr>' for i, sub in enumerate(subdomains))}
    </table>
</body>
</html>
    """

def format_vulnerability(vuln):
    """Tek bir güvenlik açığını HTML formatında döndürür"""
    severity = vuln.get('info', {}).get('severity', 'info').lower()
    return f"""
    <div class="vuln {severity}">
        <h3>{vuln.get('template-id', 'Bilinmeyen')}</h3>
        <span class="severity severity-{severity}">{severity.upper()}</span>
        <p><strong>Eşleşme:</strong> {vuln.get('host', 'N/A')}</p>
        <p><strong>Açıklama:</strong> {vuln.get('info', {}).get('description', 'Açıklama yok')}</p>
        <p><strong>Referans:</strong> {vuln.get('info', {}).get('reference', 'Referans yok')}</p>
    </div>
    """

def merge_nmap_results(input_files, output_file):
    """Nmap XML sonuçlarını birleştirir"""
    main_tree = None
    
    for file in input_files:
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            
            if main_tree is None:
                main_tree = tree
                main_root = root
                continue
            
            for host in root.findall('host'):
                main_root.append(host)
                
        except ET.ParseError as e:
            print(f"{COLOR_RED}[-] Hata: {file} işlenirken XML parse hatası: {e}{COLOR_END}")
    
    if main_tree is not None:
        main_tree.write(output_file)

def generate_report(nmap_files=None, nuclei_files=None, zap_files=None, subdomain_files=None):
    """Konsolide rapor oluşturur"""
    print(f"{COLOR_BLUE}[*] Konsolide rapor oluşturuluyor...{COLOR_END}")
    
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    output_file = f"reports/security_report_{timestamp}.xlsx"
    
    # Verileri topla
    report_data = {
        'Tarama Bilgileri': {
            'Tarih': timestamp,
            'Kullanılan Araçlar': []
        }
    }
    
    # Nmap sonuçlarını işle
    if nmap_files:
        report_data['Tarama Bilgileri']['Kullanılan Araçlar'].append('Nmap')
        for file in nmap_files:
            if file and os.path.exists(file):
                nmap_data = parse_nmap_results(file)
                report_data[f'Nmap Taraması - {os.path.basename(file)}'] = nmap_data
    
    # Nuclei sonuçlarını işle
    if nuclei_files:
        report_data['Tarama Bilgileri']['Kullanılan Araçlar'].append('Nuclei')
        for file in nuclei_files:
            if file and os.path.exists(file):
                try:
                    with open(file, 'r') as f:
                        nuclei_results = [json.loads(line) for line in f.readlines()]
                    report_data[f'Nuclei Taraması - {os.path.basename(file)}'] = {
                        'toplam': len(nuclei_results),
                        'kritik': len([v for v in nuclei_results if v.get('info', {}).get('severity', '').lower() == 'critical']),
                        'yüksek': len([v for v in nuclei_results if v.get('info', {}).get('severity', '').lower() == 'high']),
                        'orta': len([v for v in nuclei_results if v.get('info', {}).get('severity', '').lower() == 'medium']),
                        'düşük': len([v for v in nuclei_results if v.get('info', {}).get('severity', '').lower() == 'low']),
                        'bilgi': len([v for v in nuclei_results if v.get('info', {}).get('severity', '').lower() == 'info'])
                    }
                except Exception as e:
                    print(f"{COLOR_RED}[-] Nuclei sonuçları işlenirken hata: {str(e)}{COLOR_END}")
    
    # Subdomain sonuçlarını işle
    if subdomain_files:
        report_data['Tarama Bilgileri']['Kullanılan Araçlar'].append('Subdomain Tarayıcılar')
        for file in subdomain_files:
            if file and os.path.exists(file):
                with open(file, 'r') as f:
                    subdomains = f.readlines()
                report_data[f'Subdomainler - {os.path.basename(file)}'] = {
                    'toplam': len(subdomains),
                    'subdomainler': subdomains
                }
    
    # ZAP sonuçlarını işle
    if zap_files:
        report_data['Tarama Bilgileri']['Kullanılan Araçlar'].append('OWASP ZAP')
        for file in zap_files:
            if file and os.path.exists(file):
                report_data[f'ZAP Taraması - {os.path.basename(file)}'] = {
                    'rapor_dosyası': file
                }
    
    # Excel raporu oluştur
    try:
        with pd.ExcelWriter(output_file) as writer:
            for sheet_name, data in report_data.items():
                if isinstance(data, dict):
                    df = pd.DataFrame.from_dict(data, orient='index')
                    df.to_excel(writer, sheet_name=sheet_name[:31])  # Excel sheet name limit
                elif isinstance(data, list):
                    df = pd.DataFrame(data)
                    df.to_excel(writer, sheet_name=sheet_name[:31])
        
        print(f"{COLOR_GREEN}[+] Rapor oluşturuldu: {output_file}{COLOR_END}")
        return output_file
    except Exception as e:
        print(f"{COLOR_RED}[-] Rapor oluşturulurken hata: {e}{COLOR_END}")
        return None

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
    parser.add_argument('-d', '--domain', help='Taranacak domain (URL formatında)')
    parser.add_argument('-i', '--ip', help='Taranacak IP adresi veya IP bloğu')
    parser.add_argument('-m', '--mode', choices=['full', 'web', 'network', 'subdomain'], 
                       default='full', help='Tarama modu (default: full)')
    parser.add_argument('--nuclei-templates', default='~/.local/nuclei-templates', 
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
    
    try:
        # IP taraması (Nmap)
        if args.ip and args.mode in ['full', 'network']:
            nmap_results = nmap_scan(args.ip, 'full' if args.mode == 'full' else 'detailed')
        
        # Domain taraması
        if args.domain:
            domain = args.domain.split('//')[-1].split('/')[0]  # http:// varsa temizle
            
            # Subdomain keşfi
            if args.mode in ['full', 'subdomain']:
                subdomain_results = subdomain_scan(domain)
            
            # Web taramaları (ZAP ve Nuclei)
            if args.mode in ['full', 'web']:
                # ZAP taraması (sadece ana domain için)
                if args.domain.startswith(('http://', 'https://')):
                    target_url = args.domain
                else:
                    target_url = f"https://{domain}"  # Varsayılan HTTPS
                
                zap_results = run_zap_scan(target_url)
                
                # Nuclei taraması (ana domain ve subdomainler)
                nuclei_results = []
                nuclei_targets = [target_url]
                
                # Bulunan subdomainleri ekle
                if subdomain_results and os.path.exists(subdomain_results[0]):
                    with open(subdomain_results[0], 'r') as f:
                        subdomains = [line.strip() for line in f.readlines() if line.strip()]
                        nuclei_targets.extend([f"https://{sub}" for sub in subdomains])
                
                # Nuclei taraması yap
                for target in nuclei_targets:
                    nuclei_result = nuclei_scan(target, args.nuclei_templates)
                    if nuclei_result[0]:
                        nuclei_results.append(nuclei_result[0])  # JSON dosyasını ekle
        
        # Rapor oluştur
        report_file = generate_report(
            nmap_files=[nmap_results[0]] if nmap_results else None,
            nuclei_files=nuclei_results if nuclei_results else None,
            zap_files=[zap_results] if zap_results else None,
            subdomain_files=[subdomain_results[0]] if subdomain_results else None
        )
        
        print(f"{COLOR_GREEN}\n[+] Tüm taramalar başarıyla tamamlandı!{COLOR_END}")
        if report_file:
            print(f"{COLOR_GREEN}[+] Final rapor: {report_file}{COLOR_END}")
    
    except KeyboardInterrupt:
        print(f"\n{COLOR_RED}[-] Kullanıcı tarafından iptal edildi!{COLOR_END}")
        sys.exit(1)
    except Exception as e:
        print(f"{COLOR_RED}[-] Beklenmeyen hata: {str(e)}{COLOR_END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
