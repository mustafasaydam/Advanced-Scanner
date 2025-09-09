#!/bin/bash

# eximscan.sh - Eximbank İç Ağ Güvenlik Tarama Scripti
# Tüm Özellikler Dahil: Nmap + Nuclei + OWASP ZAP
# Geliştirilmiş Versiyon

# Debug modu
DEBUG=${DEBUG:-false}

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
ZAP_TIMEOUT=120

# Web portları (genişletilmiş liste)
WEB_PORTS="80,443,8080,8443,8000,8008,8081,8088,8888,9000,9080,9443,3000,5000,7000,9001"

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

# Debug log fonksiyonu
debug_log() {
    if [ "$DEBUG" = "true" ]; then
        echo -e "${MAGENTA}[DEBUG] $1${NC}"
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" >> "$LOG_DIR/debug/debug.log"
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

# Nuclei template kontrolü
check_nuclei_templates() {
    print_info "Nuclei template kontrolü..."
    
    # Template dizinini kontrol et
    local template_dir="$HOME/.local/share/nuclei/templates"
    if [ ! -d "$template_dir" ] || [ -z "$(ls -A "$template_dir" 2>/dev/null)" ]; then
        print_warning "Nuclei template'leri bulunamadı, indiriliyor..."
        nuclei -update-templates -silent > "$LOG_DIR/debug/nuclei_template_update.log" 2>&1
    fi
    
    # Template sayısını kontrol et
    local template_count=$(find "$template_dir" -name "*.yaml" 2>/dev/null | wc -l)
    print_info "Nuclei template sayısı: $template_count"
    
    if [ $template_count -lt 1000 ]; then
        print_warning "Template sayısı düşük, güncelleniyor..."
        nuclei -update-templates -silent > "$LOG_DIR/debug/nuclei_template_update.log" 2>&1
    fi
}

# ZAP bağlantı kontrolü
check_zap_ready() {
    local max_attempts=30
    local attempt=1
    
    debug_log "ZAP bağlantı kontrolü yapılıyor (attempt $attempt/$max_attempts)"
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/core/view/version" >/dev/null 2>&1; then
            debug_log "ZAP bağlantısı başarılı"
            return 0
        fi
        sleep 2
        attempt=$((attempt + 1))
        debug_log "ZAP bağlantı denemesi: $attempt/$max_attempts"
    done
    
    debug_log "ZAP bağlantı zaman aşımı"
    return 1
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
    
    # Hedefi temizle (daha akıllı yöntem)
    TARGET=$(echo "$TARGET" | sed 's|^https\?://||; s|/.*$||')
    
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
    debug_log "Hedef belirlendi: $TARGET ($TARGET_TYPE)"
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
            
            # Genişletilmiş web servis taraması
            nmap -sV --version-intensity 3 -T4 -p $WEB_PORTS "$TARGET" -oA "$nmap_output/web_scan" > "$nmap_output/nmap_web.log" 2>&1 &
            local web_pid=$!
            
            # Güvenlik açığı taraması
            nmap --script vuln --script-timeout 3m "$TARGET" -oA "$nmap_output/vuln_scan" > "$nmap_output/nmap_vuln.log" 2>&1 &
            local vuln_pid=$!
            
            # Process'leri bekle
            wait $nmap_pid $web_pid $vuln_pid
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
                nmap -sS -sV -T4 -p $WEB_PORTS "$host" -oA "$nmap_output/host_$host" >> "$nmap_output/nmap_network.log" 2>&1
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
    
    # Web servisleri bul (genişletilmiş port listesi)
    for file in "$nmap_output"/*.nmap; do
        if [ -f "$file" ]; then
            # HTTP/HTTPS portları
            grep -E "/(tcp|udp)[[:space:]]+open[[:space:]]+(http|ssl|https|http-proxy|http-alt)" "$file" | cut -d'/' -f1 >> "$LOG_DIR/web_ports.txt"
            
            # Web servisli hostlar
            local host=$(grep "Nmap scan report" "$file" | awk '{print $5}')
            if [ -n "$host" ]; then
                # Genişletilmiş web port kontrolü
                if grep -q -E "(80|443|8080|8443|8000|8008|8081|8088|8888|9000|9080|9443)/open" "$file"; then
                    echo "$host" >> "$LOG_DIR/web_hosts.txt"
                    debug_log "Web host bulundu: $host"
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
    
    # Web portlarını logla
    if [ -f "$LOG_DIR/web_ports.txt" ]; then
        local unique_ports=$(sort -u "$LOG_DIR/web_ports.txt" | tr '\n' ',' | sed 's/,$//')
        print_info "Bulunan web portları: $unique_ports"
        debug_log "Web portları: $unique_ports"
    fi
    
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
    
    # Nuclei template kontrolü ve güncellemesi
    check_nuclei_templates
    
    # Template güncellemesini bekle
    print_info "Nuclei template'leri güncelleniyor..."
    nuclei -update-templates -silent > "$LOG_DIR/debug/nuclei_update.log" 2>&1
    wait
    
    # Her web host için tarama
    for host in "${WEB_HOSTS[@]}"; do
        print_info "$host için Nuclei taraması yapılıyor..."
        
        # HTTP taraması (tüm severity seviyeleri)
        nuclei -u "http://$host" \
            -o "$LOG_DIR/nuclei/nuclei_http_$host.txt" \
            -severity critical,high,medium,low \
            -timeout 60 \
            -rate-limit 50 \
            -silent \
            > "$LOG_DIR/debug/nuclei_http_$host.log" 2>&1 &
        
        # HTTPS taraması (tüm severity seviyeleri)
        nuclei -u "https://$host" \
            -o "$LOG_DIR/nuclei/nuclei_https_$host.txt" \
            -severity critical,high,medium,low \
            -timeout 60 \
            -rate-limit 50 \
            -silent \
            > "$LOG_DIR/debug/nuclei_https_$host.log" 2>&1 &
        
        # Paralel tarama için bekleme
        sleep 2
    done
    
    # Tüm taramaların bitmesini bekle
    print_progress 15 "Nuclei taramaları tamamlanıyor"
    wait
    
    # Sonuçları kontrol et
    local findings_count=$(find "$LOG_DIR/nuclei" -name "*.txt" -exec cat {} \; | wc -l)
    print_info "Nuclei bulgu sayısı: $findings_count"
    
    print_success "Nuclei taraması tamamlandı"
}

# ZAP başlatma
start_zap() {
    print_info "OWASP ZAP başlatılıyor..."
    
    # Önceki ZAP process'lerini temizle
    pkill -f "zap.sh" >/dev/null 2>&1
    sleep 5
    
    # ZAP dizinini oluştur
    mkdir -p "$ZAP_DIR"
    
    # ZAP'ı başlat
    $ZAP_PATH -daemon -port "$ZAP_PORT" -host "$ZAP_HOST" -dir "$ZAP_DIR" \
        -config api.disablekey=true \
        -config connection.timeoutInSecs=120 \
        -config scanner.attackOnStart=true \
        -config scanner.threadPerHost=10 \
        > "$LOG_DIR/debug/zap_start.log" 2>&1 &
    
    local zap_pid=$!
    
    # ZAP'ın başlamasını bekle
    if ! check_zap_ready; then
        error_exit "ZAP başlatılamadı (timeout)"
    fi
    
    print_success "ZAP başlatıldı (Port: $ZAP_PORT)"
    sleep 5  # Ek bekleme süresi
}

# ZAP durdurma
stop_zap() {
    print_info "ZAP durduruluyor..."
    curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/core/action/shutdown/" >/dev/null 2>&1
    pkill -f "zap.sh" >/dev/null 2>&1
    sleep 5
}

# ZAP tarama fonksiyonu
run_zap_scan() {
    local target=$1
    local output_file=$2
    
    print_info "$target için ZAP aktif tarama başlatılıyor..."
    
    # Spider taraması
    local spider_id=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/spider/action/scan/?url=$target&recurse=true&maxChildren=50" | jq -r '.scan')
    
    if [ "$spider_id" = "null" ]; then
        print_warning "Spider taraması başlatılamadı, aktif tarama devam ediyor"
    else
        # Spider tamamlanmasını bekle
        local spider_status=0
        local spider_timeout=0
        while [ $spider_status -lt 100 ] && [ $spider_timeout -lt 60 ]; do
            spider_status=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/spider/view/status/?scanId=$spider_id" | jq -r '.status')
            sleep 5
            spider_timeout=$((spider_timeout + 5))
        done
    fi
    
    # Aktif tarama başlat
    local scan_id=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/ascan/action/scan/?url=$target&recurse=true&inScopeOnly=true&scanPolicyName=Default" | jq -r '.scan')
    
    if [ "$scan_id" = "null" ]; then
        print_warning "Aktif tarama başlatılamadı: $target"
        return 1
    fi
    
    # Tarama ilerlemesini takip et
    local progress=0
    local scan_timeout=0
    while [ $progress -lt 100 ] && [ $scan_timeout -lt 1800 ]; do
        progress=$(curl -s "http://$ZAP_HOST:$ZAP_PORT/JSON/ascan/view/status/?scanId=$scan_id" | jq -r '.status')
        echo -ne "\r$target tarama ilerlemesi: ${progress}% (${scan_timeout}/1800s)"
        sleep 10
        scan_timeout=$((scan_timeout + 10))
        
        if [ $progress -eq 100 ]; then
            break
        fi
    done
    echo ""
    
    if [ $progress -lt 100 ]; then
        print_warning "$target taraması zaman aşımına uğradı, sonuçlar alınıyor"
    fi
    
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
        # HTTP ve HTTPS için ayrı ayrı tarama
        run_zap_scan "http://$host" "$LOG_DIR/zap/zap_scan_http_$host.json"
        run_zap_scan "https://$host" "$LOG_DIR/zap/zap_scan_https_$host.json"
        
        # Taramalar arasında bekleme
        sleep 10
    done
    
    # ZAP'ı durdur
    stop_zap
    
    print_success "ZAP taraması tamamlandı"
}

# Rapor oluşturma
generate_reports() {
    print_header
    print_info "Güvenlik raporları oluşturuluyor..."
    
    # Tüm severity seviyelerinden bulguları hesapla
    local critical_count=$(find "$LOG_DIR" -name "*.txt" -exec grep -i "critical" {} \; | wc -l)
    local high_count=$(find "$LOG_DIR" -name "*.txt" -exec grep -i "high" {} \; | wc -l)
    local medium_count=$(find "$LOG_DIR" -name "*.txt" -exec grep -i "medium" {} \; | wc -l)
    local low_count=$(find "$LOG_DIR" -name "*.txt" -exec grep -i "low" {} \; | wc -l)
    local total_count=$((critical_count + high_count + medium_count + low_count))
    
    # ZAP bulgularını da say
    local zap_count=$(find "$LOG_DIR/zap" -name "*.json" -exec jq '.results[] | .risk' {} \; 2>/dev/null | wc -l)
    total_count=$((total_count + zap_count))
    
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
                <tr><td>Toplam Bulgular</td><td>$total_count</td></tr>
                <tr><td>Kritik Bulgular</td><td class="critical">$critical_count</td></tr>
                <tr><td>Yüksek Öncelikli Bulgular</td><td class="high">$high_count</td></tr>
                <tr><td>Orta Öncelikli Bulgular</td><td class="medium">$medium_count</td></tr>
                <tr><td>Düşük Öncelikli Bulgular</td><td class="low">$low_count</td></tr>
            </table>
        </div>

        <h2>⚠️ Kritik Bulgular</h2>
        <div class="findings">
$(find "$LOG_DIR" -name "*.txt" -exec grep -l -i "critical" {} \; | head -5 | xargs -I {} grep -i "critical" {} | head -10 || echo "Kritik bulgu bulunamadı")
        </div>

        <h2>🔴 Yüksek Öncelikli Bulgular</h2>
        <div class="findings">
$(find "$LOG_DIR" -name "*.txt" -exec grep -l -i "high" {} \; | head -5 | xargs -I {} grep -i "high" {} | head -10 || echo "Yüksek öncelikli bulgu bulunamadı")
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
            <li>Web uygulama güvenlik duvarı (WAF) kullanın</li>
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
    echo -e "${GREEN}Toplam Bulgular:${NC} $total_count"
    echo -e "${RED}Kritik Bulgular:${NC} $critical_count"
    echo -e "${YELLOW}Yüksek Öncelikli Bulgular:${NC} $high_count"
    echo -e "${BLUE}Orta Öncelikli Bulgular:${NC} $medium_count"
    echo -e "${CYAN}Düşük Öncelikli Bulgular:${NC} $low_count"
    echo -e "${CYAN}=================================================${NC}"
    echo -e "${GREEN}Rapor Dizini:${NC} $LOG_DIR"
    echo -e "${GREEN}HTML Rapor:${NC} $LOG_DIR/reports/security_report.html"
    echo -e "${CYAN}=================================================${NC}"
    
    # Debug modunda çalıştırıldıysa logları göster
    if [ "$DEBUG" = "true" ]; then
        echo -e "${YELLOW}Debug Logları:${NC} $LOG_DIR/debug/debug.log"
        echo -e "${CYAN}=================================================${NC}"
    fi
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
    # Debug modu kontrolü
    if [[ "$*" == *"--debug"* ]]; then
        DEBUG="true"
        debug_log "Debug modu etkin"
    fi
    
    main "$@"
fi
