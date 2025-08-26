#!/usr/bin/env python3
"""
Zengin Tarama Scripti - Çoklu Güvenlik Araçları Entegrasyonu
Kullanım: python zengin_tarama_scripti.py <hedef_ip>
"""

import subprocess
import sys
import os
import json
import xml.etree.ElementTree as ET
import time
from typing import List, Dict, Any, Optional
import argparse
import threading

class ZenginTarayici:
    def __init__(self, hedef_ip: str, çıktı_dizini: str = "tarama_sonuçları"):
        self.hedef_ip = hedef_ip
        self.çıktı_dizini = çıktı_dizini
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
                    # ZAP için özel kontrol (bash/zsh'de which komutu)
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
            sıra.append({'adı': 'gobuster', 'araç': 'gobuster', 'açıklama': 'Dizin/dosya ve alt alan adı keşfi'})
        
        # ZAP taramaları (otomatik ve aktif)
        if self.mevcut_araçlar['zap']:
            sıra.append({'adı': 'zap_baseline', 'araç': 'zap', 'açıklama': 'ZAP baseline taraması'})
            sıra.append({'adı': 'zap_aktif', 'araç': 'zap', 'açıklama': 'ZAP aktif güvenlik taraması'})
        
        # Özel güvenlik açığı taramaları
        if self.mevcut_araçlar['nuclei']:
            sıra.append({'adı': 'nuclei', 'araç': 'nuclei', 'açıklama': 'Nuclei güvenlik açığı taraması'})
        
        # SQL enjeksiyon testi (eğer web uygulaması varsa)
        if self.mevcut_araçlar['sqlmap']:
            sıra.append({'adı': 'sqlmap', 'araç': 'sqlmap', 'açıklama': 'SQL enjeksiyon testi'})
        
        return sıra
    
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
        çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_nmap_hizli.xml")
        komut = ["nmap", "-T4", "-F", "-oX", çıktı_dosyası, self.hedef_ip]
        print("Hızlı Nmap taraması yapılıyor...")
        
        çıktı = self.komut_çalıştır(komut)
        
        # Nmap çıktısını parse et ve port bilgilerini kaydet
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
                        'url': f"{scheme}://{self.hedef_ip}:{port_id}",
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
        çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_nmap_detaylı.xml")
        komut = ["nmap", "-T4", "-A", "-sV", "--script", "vuln", "-p", port_parametresi, "-oX", çıktı_dosyası, self.hedef_ip]
        print("Detaylı Nmap taraması yapılıyor...")
        
        return self.komut_çalıştır(komut, timeout=3600)
    
    def nikto_tarama(self) -> str:
        """Web uygulama güvenlik taraması"""
        if not self.web_servisleri:
            print("Web servisi bulunamadı, Nikto taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        for web_servis in self.web_servisleri:
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_nikto_{web_servis['port']}.txt")
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
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_dirb_{web_servis['port']}.txt")
            komut = ["dirb", web_servis['url'], "-o", çıktı_dosyası]
            print(f"DIRB dizin taraması yapılıyor: {web_servis['url']}")
            
            sonuç = self.komut_çalıştır(komut, timeout=3600)
            sonuçlar.append(çıktı_dosyası)
            
            # Bulunan dizinleri kaydet (sonraki taramalar için)
            try:
                with open(çıktı_dosyası, 'r') as f:
                    içerik = f.read()
                    # Basit bir parsing (gerçek uygulamada daha karmaşık olmalı)
                    for satır in içerik.split('\n'):
                        if '+ ' in satır and 'http' in satır:
                            self.keşfedilen_dizinler.append(satır.split('+ ')[1].strip())
            except:
                pass
        
        return ", ".join(sonuçlar)
    
    def gobuster_tarama(self) -> str:
        """Dizin/dosya ve alt alan adı keşfi"""
        if not self.web_servisleri:
            print("Web servisi bulunamadı, Gobuster taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        for web_servis in self.web_servisleri:
            # Dizin taraması
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_gobuster_dir_{web_servis['port']}.txt")
            wordlist = "/usr/share/wordlists/dirb/common.txt"  # Wordlist yolunu ayarlayın
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
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_zap_baseline_{web_servis['port']}.html")
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
    
    def zap_aktif_tarama(self) -> str:
        """ZAP aktif güvenlik taraması"""
        if not self.web_servisleri:
            print("Web servisi bulunamadı, ZAP aktif taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        for web_servis in self.web_servisleri:
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_zap_aktif_{web_servis['port']}.html")
            komut = [
                "zap.sh", "-cmd", 
                "-quickurl", web_servis['url'],
                "-quickout", çıktı_dosyası,
                "-quickprogress",
                "-config", "api.disablekey=true",
                "-config", "scanner.attackOnStart=true",
                "-config", "scanner.threadPerHost=10"
            ]
            print(f"ZAP aktif taraması yapılıyor: {web_servis['url']}")
            
            sonuç = self.komut_çalıştır(komut, timeout=7200)  # 2 saat zaman aşımı
            sonuçlar.append(çıktı_dosyası)
        
        return ", ".join(sonuçlar)
    
    def nuclei_tarama(self) -> str:
        """Nuclei güvenlik açığı taraması"""
        if not self.web_servisleri:
            print("Web servisi bulunamadı, Nuclei taraması atlanıyor.")
            return ""
        
        sonuçlar = []
        for web_servis in self.web_servisleri:
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_nuclei_{web_servis['port']}.txt")
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
            çıktı_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_sqlmap_{url.split('/')[-1]}.txt")
            komut = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=2", "--output-dir", self.çıktı_dizini]
            print(f"SQLMap testi yapılıyor: {url}")
            
            sonuç = self.komut_çalıştır(komut, timeout=3600)
            sonuçlar.append(çıktı_dosyası)
        
        return ", ".join(sonuçlar)
    
    def tarama_yap(self):
        """Taramaları belirlenen sırayla yürüt"""
        print(f"Hedef IP: {self.hedef_ip}")
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
            elif adım['adı'] == 'zap_aktif':
                sonuç = self.zap_aktif_tarama()
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
        rapor_dosyası = os.path.join(self.çıktı_dizini, f"{self.hedef_ip}_rapor.json")
        with open(rapor_dosyası, 'w') as f:
            json.dump({
                'hedef': self.hedef_ip,
                'port_bilgileri': self.port_bilgileri,
                'web_servisleri': self.web_servisleri,
                'keşfedilen_dizinler': self.keşfedilen_dizinler,
                'sonuçlar': sonuçlar
            }, f, indent=2)
        
        print(f"\nDetaylı rapor: {rapor_dosyası}")

def main():
    parser = argparse.ArgumentParser(description='Zengin Güvenlik Tarama Scripti')
    parser.add_argument('hedef', help='Hedef IP adresi veya domain')
    parser.add_argument('-o', '--output', help='Çıktı dizini', default='tarama_sonuçları')
    
    args = parser.parse_args()
    
    tarayıcı = ZenginTarayici(args.hedef, args.output)
    tarayıcı.tarama_yap()

if __name__ == "__main__":
    main()
