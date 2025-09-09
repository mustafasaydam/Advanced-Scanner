#!/bin/bash

# eximscan.sh - Eximbank İç Ağ Güvenlik Tarama Scripti
# Tüm Özellikler Dahil: Nmap + Nuclei + OWASP ZAP

# Renkli çıktılar için tanımlamalar
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Log dizini oluşturma
LOG_DIR="eximscan_$(date +%Y%m%d_%H%M%S)"
mkdir -p $LOG_DIR
mkdir -p $LOG_DIR/nmap
mkdir -p $LOG_DIR/nuclei
mkdir -p $LOG_DIR/zap
mkdir -p $LOG_DIR/debug
mkdir -p $LOG_DIR/reports

# ZAP ayarları
ZAP_PORT="8090"
ZAP_HOST="127.0.0.1"
ZAP_DIR="/root/.ZAP_$(date +%s)"
ZAP_TIMEOUT=90

# Değişkenler
TARGET=""
TARGET_TYPE=""
declare -a LIVE_HOSTS=()
declare -a WEB_HOSTS=()

# Hata fonksiyonu
error_exit() {
    echo -e "${RED}[HATA] $1${NC}" >&2
    echo -e "${RED}[HATA] Script sonlandırılıyor.${NC}" >&2
    exit 1
}

# Başlık fonksiyonu
print_header() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║               EXIMBANK SİBER GÜVENLİK TARAMASI              ║"
    echo "║                  Nmap + Nuclei + OWASP ZAP                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Bilgi fonksiyonu
print_info() {
    echo -e "${GREEN}[✓] $1${NC}"
}

# Uyarı fonksiyonu
print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# Debug fonksiyonu
print_debug() {
    echo -e "${MAGENTA}[DEBUG] $1${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" >> "$LOG_DIR/debug/debug.log"
}

# Başarı fonksiyonu
print_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Progress bar fonksiyonu
print_progress() {
    local duration=$1
    local message=$2
    echo -n -e "${BLUE}[PROGRESS] $message "
    for i in $(seq 1 $duration); do
        echo -n "."
        sleep 1
    done
    echo -e "${NC}"
}

# Bağımlılık kontrolü
check_dependencies() {
    print_info "Sistem araçları kontrol ediliyor..."
    
    local missing_tools=()
    local tools=("nmap" "nuclei" "python3" "curl" "jq" "java")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    # ZAP kontrolü
    if [ ! -f "/usr/share/zaproxy/zap.sh" ]; then
        ZAP_PATH=$(find /usr -name "zap.sh" 2>/dev/null | head -1)
        if [ -z "$ZAP_PATH" ]; then
            missing_tools+=("zap")
        else
            print_info "ZAP bulundu: $ZAP_PATH"
        fi
    else
        ZAP_PATH="/usr/share/zaproxy/zap.sh"
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        error_exit "Eksik araçlar: ${missing_tools[*]}\nLütfen 'apt install nmap nuclei python3 curl jq openjdk-17-jre zaproxy' komutu ile kurun."
    fi
    
    print_success "Tüm araçlar kurulu"
}

# Hedef ağ bilgisi
get_target() {
    print_header
    
    if [ -z "$1" ]; then
        echo -e "${YELLOW}Lütfen tarama yapılacak hedefi girin:${NC}"
        echo -e "${CYAN}Örnekler:${NC}"
        echo -e "  - Tek IP: 192.168.1.1"
        echo -e "  - Ağ range: 192.168.1.0/24"
        echo -e "  - Domain: example.com"
        echo -e "  - URL: https://example.com"
        echo ""
        read -p "Hedef: " TARGET
    else
        TARGET="$1"
    fi
    
    # Hedefi temizle
    TARGET=$(echo "$TARGET" | sed 's|https\?://||g' | sed 's|/.*||g')
    
    # Hedef tipini belirle
    if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TARGET_TYPE="ip"
    elif [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        TARGET_TYPE="network"
    elif [[ "$TARGET" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        TARGET_TYPE="domain"
    else
        error_exit "Geçersiz hedef formatı: $TARGET"
    fi
    
    echo "$TARGET" > "$LOG_DIR/target.txt"
    print_info "Hedef: $TARGET ($TARGET_TYPE)"
}

# Ağ bağlantı testi
network_test() {
    print_info "Ağ bağlantı testleri yapılıyor..."
    
    # İnternet bağlantısı testi
    if ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
        print_info "İnternet bağlantısı: Mevcut"
    else
        print_warning "İnternet bağlantısı: Yok (Nuclei güncellemeleri çalışmayabilir)"
    fi
    
    # Hedef erişim testi
    case $TARGET_TYPE in
        "ip"|"domain")
            if ping -c 3 -W 3 "$TARGET" >/dev/null 2>&1; then
                print_info "Hedefe ping: Başarılı"
                LIVE_HOSTS+=("$TARGET")
            else
                print_warning "Hedefe ping: Başarısız (port taraması deneneyecek)"
            fi
            ;;
        "network")
            print_info "Ağ range'i taraması yapılacak"
            ;;
    esac
    
    # DNS çözümleme
    if [[ "$TARGET_TYPE" == "domain" ]]; then
        if nslookup "$TARGET" > "$LOG_DIR/debug/dns_lookup.txt" 2>&1; then
            print_info "DNS çözümleme: Başarılı"
        else
            print_warning "DNS çözümleme: Başarısız"
        fi
    fi
}

# Nmap taraması
run_nmap() {
    print_header
    print_info "Nmap ile detaylı ağ taraması başlatılıyor..."
    
    local nmap_output="$LOG_DIR/nmap"
    
    case $TARGET_TYPE in
        "ip"|"domain")
            print_progress 5 "Hedef taraması"
            
            # Detaylı port taraması
            nmap -sS -sV -sC -O -T4 -p- --open "$TARGET" -oA "$nmap_output/detailed_scan" > "$nmap_output/nmap_detailed.log" 2>&1 &
            local nmap_pid=$!
            
            # Hızlı servis taraması (paralel)
            nmap -sV --version-intensity 3 -T4 -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,3306,3389,5432,6379,27017 "$TARGET" -oA "$nmap_output/quick_scan" > "$nmap_output/nmap_quick.log" 2>&1 &
            local quick_pid=$!
            
            # Güvenlik açığı taraması
            nmap --script vuln --script-timeout 2m "$TARGET" -oA "$nmap_output/vuln_scan" > "$nmap_output/nmap_vuln.log" 2>&1 &
            local vuln_pid=$!
            
            # Process'leri bekle
            wait $nmap_pid $quick_pid $vuln_pid
            ;;
        
        "network")
            print_progress 10 "Ağ keşfi yapılıyor"
            
            # Host discovery
            nmap -sn -PR "$TARGET" -oA "$nmap_output/host_discovery" > "$nmap_output/nmap_discovery.log" 2>&1
            
            # Canlı hostları bul
            grep "Status: Up" "$nmap_output/host_discovery.gnmap" | awk '{print $2}' > "$LOG_DIR/live_hosts.txt"
            mapfile -t LIVE_HOSTS < "$LOG_DIR/live_hosts.txt"
            
            if [ ${#LIVE_HOSTS[@]} -eq 0 ]; then
                print_warning "Canlı host bulunamadı"
                return 1
            fi
            
            print_info "Bulunan canlı hostlar: ${#LIVE_HOSTS[@]}"
            
            # Her host için detaylı tarama
            for host in "${LIVE_HOSTS[@]}"; do
                print_info "$host için port taraması yapılıyor..."
                nmap -sS -sV -T4 -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,3306,3389,5432,6379,27017 "$host" -oA "$nmap_output/host_$host" >> "$nmap_output/nmap_network.log" 2>&1
            done
            ;;
    esac
    
    print_success "Nmap taraması tamamlandı"
}

# Nmap sonuçlarını işle
process_nmap_results() {
    print_info "Nmap sonuçları işleniyor..."
    
    local nmap_output="$LOG_DIR/nmap"
    
    # Canlı hostları bul
    if [ ${#LIVE_HOSTS[@]} -eq 0 ]; then
        if [ -f "$nmap_output/detailed_scan.gnmap" ]; then
            grep "Status: Up" "$nmap_output/detailed_scan.gnmap" | awk '{print $2}' > "$LOG_DIR/live_hosts.txt"
            mapfile -t LIVE_HOSTS < "$LOG_DIR/live_hosts.txt"
        fi
    fi
    
    # Web servisleri bul
    for file in "$nmap_output"/*.nmap; do
        if [ -f "$file" ]; then
            # HTTP portları
            grep -oP '\d+/tcp\s+open\s+http' "$file" | cut -d'/' -f1 >> "$LOG_DIR/http_ports.txt"
            # HTTPS portları
            grep -oP '\d+/tcp\s+open\s+ssl/http' "$file" | cut -d'/' -f1 >> "$LOG_DIR/https_ports.txt"
            # Web servisli hostlar
            if grep -q "80/open\|443/open" "$file"; then
                local host=$(grep "Nmap scan report" "$file" | awk '{print $5}')
                if [ -n "$host" ]; then
                    echo "$host" >> "$LOG_DIR/web_hosts.txt"
                fi
            fi
        fi
    done
    
    # Web hostları listesini oluştur
    if [ -f "$LOG_DIR/web_hosts.txt" ]; then
        sort -u "$LOG_DIR/web_hosts.txt" > "$LOG_DIR/web_hosts_unique.txt"
        mapfile -t WEB_HOSTS < "$LOG_DIR/web_hosts_unique.txt"
    fi
    
    # Eğer web host yoksa hedefi ekle
    if [ ${#WEB_HOSTS[@]} -eq 0 ] && [ -n "$TARGET" ]; then
        WEB_HOSTS+=("$TARGET")
        echo "$TARGET" >> "$LOG_DIR/web_hosts.txt"
        print_warning "Web servisi bulunamadı, hedef web host olarak eklendi"
    fi
    
    print_info "Canlı hostlar: ${#LIVE_HOSTS[@]}"
    print_info "Web hostlar: ${#WEB_HOSTS[@]}"
    print_success "Nmap sonuçları işlendi"
}

# Nuclei taraması
run_nuclei() {
    print_header
    print_info "Nuclei güvenlik açığı taraması başlatılıyor..."
    
    if [ ${#WEB_HOSTS[@]} -eq 0 ]; then
        print_warning "Web host bulunamadı, Nuclei taraması atlanıyor"
        return 1
    fi
    
    # Nuclei template güncellemesi
    print_info "Nuclei template'leri güncelleniyor..."
    nuclei -update-templates -silent > "$LOG_DIR/debug/nuclei_update.log" 2>&1 &
    local update_pid=$!
    
    # Her web host için tarama
    for host in "${WEB_HOSTS[@]}"; do
        print_info "$host için Nuclei taraması yapılıyor..."
        
        # HTTP taraması
        nuclei -u "http://$host" \
            -o "$LOG_DIR/nuclei/nuclei_http_$host.txt" \
            -severity critical,high,medium \
            -timeout 30 \
            -rate-limit 50 \
            -silent \
            > "$LOG_DIR/debug/nuclei_http_$host.log" 2>&1 &
        
        # HTTPS taraması
        nuclei -u "https://$host" \
            -o "$LOG_DIR/nuclei/nuclei_https_$host.txt" \
            -severity critical,high,medium \
            -timeout 30 \
            -rate-limit 50 \
            -silent \
            > "$LOG_DIR/debug/nuclei_https_$host.log" 2>&1 &
        
        # Paralel tarama için bekleme
        sleep 2
    done
    
    # Template güncellemesini bekle
    wait $update_pid
    
    # Tüm taramaların bitmesini bekle
    print_progress 10 "Nuclei taramaları tamamlanıyor"
    wait
    
    print_success "Nuclei taraması tamamlandı"
}

# ZAP başlatma
start_zap() {
    print_info "OWASP ZAP başlatılıyor..."
    
    # Önceki ZAP process'lerini temizle
    pkill -f "zap.sh" >/dev/null 2>&1
    sleep 3
    
    # ZAP dizinini oluştur
    mkdir -p "$ZAP_DIR"
    
    # ZAP'ı başlat
    $ZAP_PATH -daemon -port "$ZAP_PORT" -host "$ZAP_HOST" -dir "$ZAP_DIR" \
        -config api.disablekey=true \
        -config connection.timeoutInSecs=60 \
        -config scanner.attackOnStart=true \
        > "$LOG_DIR/debug/zap_start.log" 2>&1 &
    
    local zap_pid=$!
    local timeout=$ZAP_TIMEOUT
    local count=0
    
    # ZAP'ın başlamasını bekle
    while [ $count -lt $timeout ]; do
        if curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/core/view/version" >/dev/null 2>&1; then
            print_success "ZAP başlatıldı (Port: $ZAP_PORT)"
            sleep 5  # Ek bekleme süresi
            return 0
        fi
        sleep 2
        count=$((count + 2))
        echo -ne "\rZAP başlatılıyor... ${count}/${timeout}s"
    done
    
    error_exit "ZAP başlatılamadı (timeout)"
}

# ZAP durdurma
stop_zap() {
    print_info "ZAP durduruluyor..."
    curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/core/action/shutdown/" >/dev/null 2>&1
    pkill -f "zap.sh" >/dev/null 2>&1
    sleep 3
}

# ZAP tarama fonksiyonu
run_zap_scan() {
    local target=$1
    local output_file=$2
    
    print_info "$target için ZAP aktif tarama başlatılıyor..."
    
    # Spider taraması
    local spider_id=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/spider/action/scan/?url=$target&recurse=true" | jq -r '.scan')
    
    if [ "$spider_id" = "null" ]; then
        print_warning "Spider taraması başlatılamadı, aktif tarama devam ediyor"
    else
        # Spider tamamlanmasını bekle
        local spider_status=0
        while [ $spider_status -lt 100 ]; do
            spider_status=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/spider/view/status/?scanId=$spider_id" | jq -r '.status')
            sleep 5
        done
    fi
    
    # Aktif tarama başlat
    local scan_id=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/ascan/action/scan/?url=$target&recurse=true&inScopeOnly=true" | jq -r '.scan')
    
    if [ "$scan_id" = "null" ]; then
        print_warning "Aktif tarama başlatılamadı: $target"
        return 1
    fi
    
    # Tarama ilerlemesini takip et
    local progress=0
    while [ $progress -lt 100 ]; do
        progress=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/ascan/view/status/?scanId=$scan_id" | jq -r '.status')
        echo -ne "\r$target tarama ilerlemesi: ${progress}%"
        sleep 10
        
        if [ $progress -eq 100 ]; then
            break
        fi
    done
    echo ""
    
    # Sonuçları al
    curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/ascan/view/results/?scanId=$scan_id" | jq '.' > "$output_file"
    
    # HTML raporu oluştur
    curl -s "http://$ZAP_HOST:$ZAP_PORT/OTHER/core/other/htmlreport/" > "${output_file%.*}_report.html"
    
    # XML raporu oluştur
    curl -s "http://$ZAP_HOST:$ZAP_PORT/OTHER/core/other/xmlreport/" > "${output_file%.*}_report.xml"
    
    print_info "$target ZAP taraması tamamlandı"
}

# ZAP taraması
run_zap_scans() {
    print_header
    print_info "OWASP ZAP web uygulama güvenlik testi başlatılıyor..."
    
    if [ ${#WEB_HOSTS[@]} -eq 0 ]; then
        print_warning "Web host bulunamadı, ZAP taraması atlanıyor"
        return 1
    fi
    
    # ZAP'ı başlat
    start_zap
    
    # Her web host için ZAP taraması
    for host in "${WEB_HOSTS[@]}"; do
        run_zap_scan "http://$host" "$LOG_DIR/zap/zap_scan_$host.json"
        
        # Taramalar arasında bekleme
        sleep 5
    done
    
    # ZAP'ı durdur
    stop_zap
    
    print_success "ZAP taraması tamamlandı"
}

# Rapor oluşturma
generate_reports() {
    print_header
    print_info "Güvenlik raporları oluşturuluyor..."
    
    # Toplam bulguları hesapla
    local critical_count=$(find "$LOG_DIR" -name "*.txt" -exec grep -i "critical" {} \; | wc -l)
    local high_count=$(find "$LOG_DIR" -name "*.txt" -exec grep -i "high" {} \; | wc -l)
    local medium_count=$(find "$LOG_DIR" -name "*.txt" -exec grep -i "medium" {} \; | wc -l)
    
    # HTML raporu oluştur
    cat > "$LOG_DIR/reports/security_report.html" << EOF
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Eximbank Güvenlik Tarama Raporu</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .summary-card {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
        }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; font-weight: bold; }
        .medium { color: #f39c12; }
        .low { color: #3498db; }
        .info { color: #27ae60; }
        .findings {
            background: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #3498db;
            margin: 10px 0;
            font-family: monospace;
            white-space: pre-wrap;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #34495e;
            color: white;
        }
        tr:hover { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Eximbank Güvenlik Tarama Raporu</h1>
        <p><strong>Tarama Tarihi:</strong> $(date)</p>
        <p><strong>Hedef:</strong> $TARGET ($TARGET_TYPE)</p>
        
        <div class="summary-card">
            <h2>📊 Tarama Özeti</h2>
            <table>
                <tr>
                    <th>Metrik</th>
                    <th>Değer</th>
                </tr>
                <tr><td>Canlı Hostlar</td><td>${#LIVE_HOSTS[@]}</td></tr>
                <tr><td>Web Hostlar</td><td>${#WEB_HOSTS[@]}</td></tr>
                <tr><td>Kritik Bulgular</td><td class="critical">$critical_count</td></tr>
                <tr><td>Yüksek Öncelikli Bulgular</td><td class="high">$high_count</td></tr>
                <tr><td>Orta Öncelikli Bulgular</td><td class="medium">$medium_count</td></tr>
            </table>
        </div>

        <h2>⚠️ Kritik Bulgular</h2>
        <div class="findings">
$(find "$LOG_DIR" -name "*.txt" -exec grep -l -i "critical" {} \; | head -3 | xargs -I {} grep -i "critical" {} | head -5 || echo "Kritik bulgu bulunamadı")
        </div>

        <h2>🔴 Yüksek Öncelikli Bulgular</h2>
        <div class="findings">
$(find "$LOG_DIR" -name "*.txt" -exec grep -l -i "high" {} \; | head -3 | xargs -I {} grep -i "high" {} | head -5 || echo "Yüksek öncelikli bulgu bulunamadı")
        </div>

        <h2>📋 Detaylı Raporlar</h2>
        <ul>
            <li><a href="../nmap/detailed_scan.nmap">Nmap Detaylı Tarama</a></li>
            <li><a href="../nmap/vuln_scan.nmap">Nmap Güvenlik Açığı Taraması</a></li>
            <li><a href="../nuclei/">Nuclei Sonuçları</a></li>
            <li><a href="../zap/">ZAP Sonuçları</a></li>
            <li><a href="../debug/">Debug Logları</a></li>
        </ul>

        <h2>🎯 Öneriler</h2>
        <ul>
            <li>Kritik ve yüksek öncelikli bulguları acilen düzeltin</li>
            <li>Düzenli güvenlik taramaları planlayın</li>
            <li>Sistemlerinizi güncel tutun</li>
            <li>Güvenlik duvarı kurallarını gözden geçirin</li>
        </ul>
    </div>
</body>
</html>
EOF

    # Konsol özeti
    print_header
    print_success "TARAMA TAMAMLANDI"
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${GREEN}Hedef:${NC} $TARGET"
    echo -e "${GREEN}Canlı Hostlar:${NC} ${#LIVE_HOSTS[@]}"
    echo -e "${GREEN}Web Hostlar:${NC} ${#WEB_HOSTS[@]}"
    echo -e "${RED}Kritik Bulgular:${NC} $critical_count"
    echo -e "${YELLOW}Yüksek Öncelikli Bulgular:${NC} $high_count"
    echo -e "${BLUE}Orta Öncelikli Bulgular:${NC} $medium_count"
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${GREEN}Rapor Dizini:${NC} $LOG_DIR"
    echo -e "${GREEN}HTML Rapor:${NC} $LOG_DIR/reports/security_report.html"
    echo -e "${CYAN}=================================================${NC}"
}

# Ana fonksiyon
main() {
    print_header
    
    # Bağımlılık kontrolü
    check_dependencies
    
    # Hedef belirleme
    if [ -n "$1" ]; then
        get_target "$1"
    else
        get_target
    fi
    
    # Ağ testi
    network_test
    
    # Nmap taraması
    run_nmap
    
    # Sonuçları işle
    process_nmap_results
    
    # Nuclei taraması
    run_nuclei
    
    # ZAP taraması
    run_zap_scans
    
    # Rapor oluştur
    generate_reports
    
    # Temizlik
    if [ -d "$ZAP_DIR" ]; then
        rm -rf "$ZAP_DIR"
    fi
}

# Hata yakalama
trap 'error_exit "Script beklenmeyen bir hatayla karşılaştı: $?"' ERR

# Scripti çalıştır
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
