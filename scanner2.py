#!/usr/bin/env python3
"""
Zengin Tarama Scripti - Çoklu Güvenlik Araçları Entegrasyonu
Kullanım: python zengin_tarama_scripti.py <hedef> [options]
"""

import subprocess
import sys
import os
import json
import xml.etree.ElementTree as ET
import time
from typing import List, Dict, Any, Optional
import argparse
import ipaddress
import socket

class ZenginTarayici:
    def __init__(self, hedef: str, çıktı_dizini: str = "tarama_sonuçları", özel_portlar: List[str] = None):
        self.hedef = hedef
        self.çıktı_dizini = çıktı_dizini
        self.özel_portlar = özel_portlar or []
        self.port_bilgileri = {}
        self.web_servisleri = []
        self.keşfedilen_dizinler = []
        
        # Çıktı dizinini oluştur
        os.makedirs(çıktı_dizini, exist_ok=True)
        
        # Mevcut araçların kontrolü
        self.mevcut_araçlar = self._araçları_kontrol_et()
        
        # Kullanılacak araçlar ve sıraları
        self.tarama_sırası = self._tarama_sırasını_belirle()
    
    def _araçları_kontrol_et(self) -> Dict[str, bool]:
        """Sistemde hangi güvenlik araçlarının kurulu olduğunu kontrol et"""
        araçlar = {
            'nmap': False,
            'zap': False,
            'nikto': False,
            'dirb': False,
            'gobuster': False,
            'sqlmap': False,
            'nuclei': False
        }
        
        for arac in araçlar.keys():
            try:
                if arac == 'zap':
                    # ZAP için özel kontrol
                    result = subprocess.run(['which', 'zap.sh'], capture_output=True, text=True)
                    araçlar[arac] = result.returncode == 0
                else:
                    result = subprocess.run([arac, '--version'], capture_output=True, text=True)
                    araçlar[arac] = result.returncode == 0
            except FileNotFoundError:
                pass
        
        return araçlar
    
    def _tarama_sırasını_belirle(self) -> List[Dict[str, Any]]:
        """Mevcut araçlara göre tarama sırasını belirle"""
        sıra = []
        
        # Port tarama ve servis keşfi
        if self.mevcut_araçlar['nmap']:
            sıra.append({'adı': 'nmap_hizli', 'araç': 'nmap', 'açıklama': 'Hızlı port taraması'})
            sıra.append({'adı': 'nmap_detaylı', 'araç': 'nmap', 'açıklama': 'Detaylı servis taraması'})
        
        # Web güvenlik taramaları
        if self.mevcut_araçlar['nikto']:
            sıra.append({'adı': 'nikto', 'araç': 'nikto', 'açıklama': 'Web uygulama güvenlik taraması'})
        
        if self.mevcut_araçlar['dirb']:
            sıra.append({'adı': 'dirb', 'araç': 'dirb', 'açıklama': 'Dizin ve dosya keşfi'})
        
        if self.mevcut_araçlar['gobuster']:
            sıra.append({'adı': 'gobuster', 'araç': 'gobuster', 'açıklama': 'Dizin/dosya keşfi'})
        
        # ZAP taramaları
        if self.mevcut_araçlar['zap']:
            sıra.append({'adı': 'zap_baseline', 'araç': 'zap', 'açıklama': 'ZAP baseline taraması'})
        
        # Özel güvenlik açığı taramaları
        if self.mevcut_araçlar['nuclei']:
            sıra.append({'adı': 'nuclei', 'araç': 'nuclei', 'açıklama': 'Nuclei güvenlik açığı taraması'})
        
        # SQL enjeksiyon testi
        if self.mevcut_araçlar['sqlmap']:
            sıra.append({'adı': 'sqlmap', 'araç': 'sqlmap', 'açıklama': 'SQL enjeksiyon testi'})
        
        return sıra
    
    def _hedef_ip_mi(self) -> bool:
        """Hedefin IP adresi olup olmadığını kontrol et"""
        try:
            ipaddress.ip_address(self.hedef)
            return True
        except ValueError:
            return False
    
    def _ip_çözümle(self) -> str:
        """Domain'i IP'ye çözümle"""
        if self._hedef_ip_mi():
            return self.hedef
        
        try:
            return socket.gethostbyname(self.hedef)
        except socket.gaierror:
            print(f"Domain çözümlenemedi: {self.hedef}")
            return self.hedef
    
    def komut_çalıştır(self, komut: List[str], çıktı_dosyası: str = None, timeout: int = 1800) -> str:
        """Shell komutu çalıştır ve çıktıyı döndür"""
        try:
            if çıktı_dosyası:
                with open(çıktı_dosyası, 'w') as f:
                    sonuç = subprocess.run(
                        komut, 
                        stdout=f, 
                        stderr=subprocess.PIPE, 
                        text=True,
                        timeout=timeout
                    )
            else:
                sonuç = subprocess.run(
                    komut, 
                    capture_output=True, 
                    text=True,
                    timeout=timeout
                )
            
            if sonuç.returncode != 0:
                print(f"Hata: {sonuç.stderr}")
                return ""
                
            return sonuç.stdout if not çıktı_dosyası else f"Çıktı {çıktı_dosyası} dosyasına kaydedildi"
            
        except subprocess.TimeoutExpired:
            print(f"Komut zaman aşımına uğradı: {' '.join(komut)}")
            return "ZAMAN_AŞIMI"
        except Exception as e:
            print(f"Komut çalıştırma hatası: {e}")
            return ""
    
    def nmap_hizli_tarama(self) -> str:
        """Hızlı port taraması"""
        çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef}_nmap_hizli.xml")
        
        if self.özel_portlar:
            # Özel port taraması
            port_parametresi = ",".join(self.özel_portlar)
            komut = ["nmap", "-T4", "-p", port_parametresi, "-oX", çıktı_dosyası, self.hedef]
            print(f"Özel port taraması yapılıyor: {port_parametresi}")
        else:
            # Hızlı port taraması (top 1000 port)
            komut = ["nmap", "-T4", "--top-ports", "1000", "-oX", çıktı_dosyası, self.hedef]
            print("Hızlı Nmap taraması yapılıyor (top 1000 port)...")
        
        çıktı = self.komut_çalıştır(komut)
        
        # Nmap çıktısını parse et
        try:
            tree = ET.parse(çıktı_dosyası)
            root = tree.getroot()
            
            for port in root.findall(".//port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                state = port.find("state").get("state")
                service = port.find("service").get("name") if port.find("service") is not None else "unknown"
                
                self.port_bilgileri[port_id] = {
                    "protocol": protocol,
                    "state": state,
                    "service": service
                }
                
                # Web servislerini tespit et
                if service in ['http', 'https', 'http-proxy', 'http-alt']:
                    scheme = 'https' if service == 'https' else 'http'
                    self.web_servisleri.append({
                        'url': f"{scheme}://{self.hedef}:{port_id}",
                        'port': port_id,
                        'scheme': scheme
                    })
                    
        except Exception as e:
            print(f"Nmap çıktısı parse hatası: {e}")
        
        return çıktı_dosyası
    
    def nmap_detaylı_tarama(self) -> str:
        """Açık portlara detaylı tarama"""
        açık_portlar = [port for port, info in self.port_bilgileri.items() if info['state'] == 'open']
        
        if not açık_portlar:
            print("Açık port bulunamadı, detaylı tarama atlanıyor.")
            return ""
        
        port_parametresi = ",".join(açık_portlar)
        çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef}_nmap_detaylı.xml")
        komut = ["nmap", "-T4", "-A", "-sV", "-p", port_parametresi, "-oX", çıktı_dosyası, self.hedef]
        print("Detaylı Nmap taraması yapılıyor...")
        
        return self.komut_çalıştır(komut, timeout=3600)
    
    def nikto_tarama(self) -> str:
        """Web uygulama güvenlik taraması"""
        if not self.web_servisleri:
            print("Web servisi bulunamadı, Nikto taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        for web_servis in self.web_servisleri:
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef}_nikto_{web_servis['port']}.txt")
            komut = ["nikto", "-h", web_servis['url'], "-o", çıktı_dosyası, "-Format", "txt"]
            print(f"Nikto web taraması yapılıyor: {web_servis['url']}")
            
            sonuç = self.komut_çalıştır(komut, timeout=1800)
            sonuçlar.append(çıktı_dosyası)
        
        return ", ".join(sonuçlar)
    
    def dirb_tarama(self) -> str:
        """Dizin ve dosya keşfi"""
        if not self.web_servisleri:
            print("Web servisi bulunamadı, DIRB taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        for web_servis in self.web_servisleri:
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef}_dirb_{web_servis['port']}.txt")
            komut = ["dirb", web_servis['url'], "-o", çıktı_dosyası]
            print(f"DIRB dizin taraması yapılıyor: {web_servis['url']}")
            
            sonuç = self.komut_çalıştır(komut, timeout=3600)
            sonuçlar.append(çıktı_dosyası)
            
            # Bulunan dizinleri kaydet (sonraki taramalar için)
            try:
                with open(çıktı_dosyası, 'r') as f:
                    içerik = f.read()
                    # Basit parsing
                    for satır in içerik.split('\n'):
                        if '+ ' in satır and 'http' in satır:
                            self.keşfedilen_dizinler.append(satır.split('+ ')[1].strip())
            except:
                pass
        
        return ", ".join(sonuçlar)
    
    def gobuster_tarama(self) -> str:
        """Dizin/dosya keşfi"""
        if not self.web_servisleri:
            print("Web servisi bulunamadı, Gobuster taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        for web_servis in self.web_servisleri:
            # Dizin taraması
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef}_gobuster_dir_{web_servis['port']}.txt")
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            if not os.path.exists(wordlist):
                wordlist = "/usr/share/dirb/wordlists/common.txt"
            
            komut = ["gobuster", "dir", "-u", web_servis['url'], "-w", wordlist, "-o", çıktı_dosyası]
            print(f"Gobuster dizin taraması yapılıyor: {web_servis['url']}")
            
            sonuç = self.komut_çalıştır(komut, timeout=3600)
            sonuçlar.append(çıktı_dosyası)
        
        return ", ".join(sonuçlar)
    
    def zap_baseline_tarama(self) -> str:
        """ZAP baseline taraması"""
        if not self.web_servisleri:
            print("Web servisi bulunamadı, ZAP taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        for web_servis in self.web_servisleri:
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef}_zap_baseline_{web_servis['port']}.html")
            komut = [
                "zap.sh", "-cmd", 
                "-quickurl", web_servis['url'],
                "-quickout", çıktı_dosyası,
                "-quickprogress"
            ]
            print(f"ZAP baseline taraması yapılıyor: {web_servis['url']}")
            
            sonuç = self.komut_çalıştır(komut, timeout=3600)
            sonuçlar.append(çıktı_dosyası)
        
        return ", ".join(sonuçlar)
    
    def nuclei_tarama(self) -> str:
        """Nuclei güvenlik açığı taraması"""
        if not self.web_servisleri:
            print("Web servisi bulunamadı, Nuclei taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        for web_servis in self.web_servisleri:
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef}_nuclei_{web_servis['port']}.txt")
            komut = ["nuclei", "-u", web_servis['url'], "-o", çıktı_dosyası]
            print(f"Nuclei güvenlik açığı taraması yapılıyor: {web_servis['url']}")
            
            sonuç = self.komut_çalıştır(komut, timeout=3600)
            sonuçlar.append(çıktı_dosyası)
        
        return ", ".join(sonuçlar)
    
    def sqlmap_tarama(self) -> str:
        """SQL enjeksiyon testi"""
        if not self.keşfedilen_dizinler:
            print("Test edilecek URL bulunamadı, SQLMap taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        test_edilecek_urls = self.keşfedilen_dizinler[:3]  # İlk 3 URL'yi test et
        
        for url in test_edilecek_urls:
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef}_sqlmap_{url.split('/')[-1]}.txt")
            komut = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1", "--output-dir", self.çıktı_dizini]
            print(f"SQLMap testi yapılıyor: {url}")
            
            sonuç = self.komut_çalıştır(komut, timeout=3600)
            sonuçlar.append(çıktı_dosyası)
        
        return ", ".join(sonuçlar)
    
    def tarama_yap(self):
        """Taramaları belirlenen sırayla yürüt"""
        print(f"Hedef: {self.hedef}")
        print(f"IP Adresi: {self._ip_çözümle()}")
        print(f"Tespit edilen araçlar: {[k for k, v in self.mevcut_araçlar.items() if v]}")
        print(f"Tarama sırası: {[adım['adı'] for adım in self.tarama_sırası]}")
        print("=" * 50)
        
        sonuçlar = {}
        
        for i, adım in enumerate(self.tarama_sırası):
            print(f"\n[{i+1}/{len(self.tarama_sırası)}] {adım['açıklama']} yapılıyor...")
            
            başlangıç_zamanı = time.time()
            
            # İlgili tarama fonksiyonunu çağır
            if adım['adı'] == 'nmap_hizli':
                sonuç = self.nmap_hizli_tarama()
            elif adım['adı'] == 'nmap_detaylı':
                sonuç = self.nmap_detaylı_tarama()
            elif adım['adı'] == 'nikto':
                sonuç = self.nikto_tarama()
            elif adım['adı'] == 'dirb':
                sonuç = self.dirb_tarama()
            elif adım['adı'] == 'gobuster':
                sonuç = self.gobuster_tarama()
            elif adım['adı'] == 'zap_baseline':
                sonuç = self.zap_baseline_tarama()
            elif adım['adı'] == 'nuclei':
                sonuç = self.nuclei_tarama()
            elif adım['adı'] == 'sqlmap':
                sonuç = self.sqlmap_tarama()
            else:
                sonuç = "Bilinmeyen tarama adımı"
            
            süre = time.time() - başlangıç_zamanı
            sonuçlar[adım['adı']] = {
                'sonuç': sonuç,
                'süre': süre
            }
            
            print(f"{adım['açıklama']} tamamlandı ({süre:.2f} saniye)")
        
        # Sonuçları özetle
        print(f"\n{'='*50}\nTARAMA TAMAMLANDI\n{'='*50}")
        for adım, bilgi in sonuçlar.items():
            print(f"{adım}: {bilgi['sonuç']} ({bilgi['süre']:.2f}s)")
        
        # JSON formatında sonuçları kaydet
        rapor_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef}_rapor.json")
        with open(rapor_dosyası, 'w') as f:
            json.dump({
                'hedef': self.hedef,
                'ip_adresi': self._ip_çözümle(),
                'port_bilgileri': self.port_bilgileri,
                'web_servisleri': self.web_servisleri,
                'keşfedilen_dizinler': self.keşfedilen_dizinler,
                'sonuçlar': sonuçlar
            }, f, indent=2)
        
        print(f"\nDetaylı rapor: {rapor_dosyası}")

def ip_aralığı_oluştur(başlangıç: str, bitiş: str) -> List[str]:
    """IP aralığı oluştur"""
    ip_listesi = []
    try:
        start_ip = ipaddress.ip_address(başlangıç)
        end_ip = ipaddress.ip_address(bitiş)
        
        current_ip = start_ip
        while current_ip <= end_ip:
            ip_listesi.append(str(current_ip))
            current_ip += 1
            
    except ValueError as e:
        print(f"Geçersiz IP aralığı: {e}")
    
    return ip_listesi

def main():
    parser = argparse.ArgumentParser(description='Zengin Güvenlik Tarama Scripti')
    parser.add_argument('hedef', nargs='?', help='Hedef IP adresi, domain veya IP aralığı (örn: 192.168.1.1-192.168.1.10)')
    parser.add_argument('-o', '--output', help='Çıktı dizini', default='tarama_sonuçları')
    parser.add_argument('-p', '--ports', help='Özel portlar (örn: 80,443,8080)', default='')
    parser.add_argument('-l', '--list', help='IP listesi dosyası', default='')
    
    args = parser.parse_args()
    
    if not args.hedef and not args.list:
        parser.print_help()
        sys.exit(1)
    
    # Özel portları ayır
    özel_portlar = []
    if args.ports:
        özel_portlar = [p.strip() for p in args.ports.split(',') if p.strip()]
    
    # IP listesi oluştur
    hedefler = []
    
    if args.list:
        # Dosyadan IP listesi oku
        try:
            with open(args.list, 'r') as f:
                for satır in f:
                    satır = satır.strip()
                    if satır and not satır.startswith('#'):
                        hedefler.append(satır)
        except FileNotFoundError:
            print(f"Dosya bulunamadı: {args.list}")
            sys.exit(1)
    elif args.hedef and '-' in args.hedef:
        # IP aralığı
        başlangıç, bitiş = args.hedef.split('-', 1)
        hedefler = ip_aralığı_oluştur(başlangıç.strip(), bitiş.strip())
    else:
        # Tek hedef
        hedefler = [args.hedef]
    
    print(f"Taranacak hedef sayısı: {len(hedefler)}")
    
    for i, hedef in enumerate(hedefler):
        print(f"\n{'='*50}")
        print(f"[{i+1}/{len(hedefler)}] {hedef} taranıyor...")
        print(f"{'='*50}")
        
        try:
            tarayıcı = ZenginTarayici(hedef, args.output, özel_portlar)
            tarayıcı.tarama_yap()
            
            # Hedefler arasında bekleme
            if i < len(hedefler) - 1:
                print(f"\n5 saniye bekleniyor...")
                time.sleep(5)
                
        except Exception as e:
            print(f"{hedef} taramasında hata: {e}")
            continue

if __name__ == "__main__":
    main()
