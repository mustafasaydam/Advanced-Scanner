#!/bin/bash

# eximscan.sh - Eximbank İç Ağ Güvenlik Tarama Scripti
# Siber Güvenlik Ekibi için Özel Olarak Geliştirilmiştir

# Renkli çıktılar için tanımlamalar
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log dizini oluşturma
LOG_DIR="eximscan_$(date +%Y%m%d_%H%M%S)"
mkdir -p $LOG_DIR
mkdir -p $LOG_DIR/nmap
mkdir -p $LOG_DIR/nuclei
mkdir -p $LOG_DIR/zap

# Hata fonksiyonu
error_exit() {
    echo -e "${RED}[HATA] $1${NC}" >&2
    exit 1
}

# Başlık fonksiyonu
print_header() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "   EXIMBANK SİBER GÜVENLİK TARAMASI"
    echo "========================================"
    echo -e "${NC}"
}

# Bilgi fonksiyonu
print_info() {
    echo -e "${GREEN}[BİLGİ] $1${NC}"
}

# Uyarı fonksiyonu
print_warning() {
    echo -e "${YELLOW}[UYARI] $1${NC}"
}

# Bağımlılık kontrolü
check_dependencies() {
    print_info "Araçlar kontrol ediliyor..."
    
    command -v nmap >/dev/null 2>&1 || error_exit "nmap kurulu değil"
    command -v nuclei >/dev/null 2>&1 || error_exit "nuclei kurulu değil"
    command -v zap-cli >/dev/null 2>&1 || error_exit "zap-cli kurulu değil"
    command -v python3 >/dev/null 2>&1 || error_exit "python3 kurulu değil"
    
    print_info "Tüm araçlar kurulu ✓"
}

# Hedef ağ bilgisi
get_target() {
    echo -e "${YELLOW}Taramak istediğiniz ağ/IP/CIDR girin (örn: 192.168.1.0/24):${NC}"
    read -p "Hedef: " TARGET
    echo "$TARGET" > $LOG_DIR/target.txt
}

# Nmap taraması
run_nmap() {
    print_header
    print_info "Nmap ile keşif ve servis taraması başlatılıyor..."
    
    # Host keşfi
    nmap -sn $TARGET -oA $LOG_DIR/nmap/host_discovery
    
    # Detaylı tarama
    nmap -sS -sV -sC -O -T4 -p- --open $TARGET -oA $LOG_DIR/nmap/detailed_scan
    
    # Servis ve versiyon taraması
    nmap -sV --version-intensity 5 $TARGET -oA $LOG_DIR/nmap/version_scan
    
    # Güvenlik açığı taraması
    nmap --script vuln $TARGET -oA $LOG_DIR/nmap/vuln_scan
    
    print_info "Nmap taraması tamamlandı ✓"
}

# Nmap sonuçlarını parse etme
parse_nmap_results() {
    print_info "Nmap sonuçları işleniyor..."
    
    # HTTP/HTTPS servisleri tespit et
    grep -oP '\d+/tcp\s+open\s+http' $LOG_DIR/nmap/detailed_scan.nmap | cut -d'/' -f1 > $LOG_DIR/http_ports.txt
    grep -oP '\d+/tcp\s+open\s+ssl/http' $LOG_DIR/nmap/detailed_scan.nmap | cut -d'/' -f1 >> $LOG_DIR/https_ports.txt
    
    # Canlı hostları listele
    grep "Nmap scan report" $LOG_DIR/nmap/host_discovery.nmap | awk '{print $5}' > $LOG_DIR/live_hosts.txt
    
    print_info "Nmap sonuçları işlendi ✓"
}

# Nuclei taraması
run_nuclei() {
    print_header
    print_info "Nuclei ile güvenlik açığı taraması başlatılıyor..."
    
    # Tüm hostlar için nuclei taraması
    while read host; do
        print_info "$host için nuclei taraması yapılıyor..."
        nuclei -u http://$host -o $LOG_DIR/nuclei/nuclei_http_$host.txt -severity critical,high,medium &
        nuclei -u https://$host -o $LOG_DIR/nuclei/nuclei_https_$host.txt -severity critical,high,medium &
    done < $LOG_DIR/live_hosts.txt
    
    wait
    
    # Özel portlar için tarama
    while read port; do
        while read host; do
            nuclei -u http://$host:$port -o $LOG_DIR/nuclei/nuclei_${host}_port_${port}.txt -severity critical,high &
        done < $LOG_DIR/live_hosts.txt
    done < $LOG_DIR/http_ports.txt
    
    wait
    
    print_info "Nuclei taraması tamamlandı ✓"
}

# ZAP taraması
run_zap() {
    print_header
    print_info "OWASP ZAP ile web uygulama güvenlik testi başlatılıyor..."
    
    # ZAP baseline taraması
    while read host; do
        print_info "$host için ZAP taraması yapılıyor..."
        zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' $host -o $LOG_DIR/zap/zap_scan_$host.txt &
    done < $LOG_DIR/live_hosts.txt
    
    wait
    
    # Aktif tarama
    while read host; do
        print_info "$host için ZAP aktif tarama yapılıyor..."
        zap-cli active-scan --scanners all $host -o $LOG_DIR/zap/zap_active_$host.txt &
    done < $LOG_DIR/live_hosts.txt
    
    wait
    
    print_info "ZAP taraması tamamlandı ✓"
}

# Rapor oluşturma
generate_report() {
    print_header
    print_info "Güvenlik raporu oluşturuluyor..."
    
    # HTML raporu oluştur
    cat > $LOG_DIR/security_report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Eximbank Güvenlik Tarama Raporu</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; font-weight: bold; }
        .medium { color: #ffcc00; }
        .low { color: #3366ff; }
        .info { color: #33cc33; }
    </style>
</head>
<body>
    <h1>Eximbank İç Ağ Güvenlik Tarama Raporu</h1>
    <p>Tarama Tarihi: $(date)</p>
    <p>Hedef: $TARGET</p>
    
    <h2>Özet</h2>
    <ul>
        <li>Canlı Hostlar: $(wc -l < $LOG_DIR/live_hosts.txt)</li>
        <li>HTTP Portları: $(wc -l < $LOG_DIR/http_ports.txt)</li>
        <li>HTTPS Portları: $(wc -l < $LOG_DIR/https_ports.txt)</li>
    </ul>
    
    <h2>Kritik Bulgular</h2>
    <pre>$(grep -r "critical" $LOG_DIR/nuclei/ $LOG_DIR/zap/ | head -20)</pre>
    
    <h2>Yüksek Öncelikli Bulgular</h2>
    <pre>$(grep -r "high" $LOG_DIR/nuclei/ $LOG_DIR/zap/ | head -20)</pre>
    
    <h2>Detaylı Raporlar</h2>
    <ul>
        <li><a href="nmap/detailed_scan.nmap">Nmap Detaylı Tarama</a></li>
        <li><a href="nmap/vuln_scan.nmap">Nmap Güvenlik Açığı Taraması</a></li>
        <li><a href="nuclei/">Nuclei Sonuçları</a></li>
        <li><a href="zap/">ZAP Sonuçları</a></li>
    </ul>
</body>
</html>
EOF

    print_info "Rapor oluşturuldu: $LOG_DIR/security_report.html"
}

# Ana fonksiyon
main() {
    print_header
    print_info "Eximbank Güvenlik Tarama Scripti Başlatılıyor 🚀"
    
    # Bağımlılık kontrolü
    check_dependencies
    
    # Hedef belirleme
    get_target
    
    # Taramaları çalıştır
    run_nmap
    parse_nmap_results
    run_nuclei
    run_zap
    
    # Rapor oluştur
    generate_report
    
    print_header
    print_info "Tüm taramalar tamamlandı! ✅"
    print_info "Sonuçlar: $LOG_DIR dizininde"
    print_warning "Lütfen bulguları manuel olarak doğrulayın!"
    
    # Kritik bulguları göster
    echo -e "${RED}"
    echo "=== KRİTİK BULGULAR ==="
    grep -r "critical" $LOG_DIR/nuclei/ $LOG_DIR/zap/ | head -10
    echo -e "${NC}"
}

# Scripti çalıştır
main "$@"
