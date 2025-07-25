#!/bin/bash

# ZAP tarama fonksiyonu
run_zap_scan() {
  local target="$1"
  local output="$2"
  local config="$3"
  local mode="$4"

  echo -e "\n${YELLOW}[*] Starting ZAP Scan...${NC}"

  # Config dosyasından ayarları oku
  local zap_api_key=$(yq e '.zap.api_key' "$config")
  local zap_active_scan=$(yq e '.zap.active_scan' "$config")
  local zap_spider_timeout=$(yq e '.zap.spider_timeout' "$config")

  # Moda göre ayarları uyarla
  case "$mode" in
    "quick")
      zap_active_scan="false"
      zap_spider_timeout=5
      ;;
    "deep")
      zap_spider_timeout=30
      ;;
  esac

  local output_file="$output/scans/zap_scan.json"

  # ZAP komutunu oluştur ve çalıştır
  local zap_cmd="zap-cli --zap-path /usr/share/zaproxy/zap.sh quick-scan \
  --spider --ajax-spider --active-scan $zap_active_scan \
  --spider-mins $zap_spider_timeout --api-key $zap_api_key \
  -r -f json -o $output_file $target"
  echo -e "${YELLOW}[COMMAND] $zap_cmd${NC}"
  
  if eval "$zap_cmd"; then
    echo -e "${GREEN}[+] ZAP scan completed successfully${NC}"
    
    # JSON raporunu işle
    jq '.' "$output_file" > "$output/reports/zap_scan.txt" || \
    echo -e "${RED}[-] ZAP report generation failed${NC}"
  else
    error_exit "ZAP scan failed"
  fi
}
