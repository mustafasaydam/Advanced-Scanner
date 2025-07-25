#!/bin/bash

# Nuclei tarama fonksiyonu
run_nuclei_scan() {
  local target="$1"
  local output="$2"
  local config="$3"
  local mode="$4"

  echo -e "\n${YELLOW}[*] Starting Nuclei Scan...${NC}"

  # Config dosyasından ayarları oku
  local nuclei_templates=$(yq e '.nuclei.templates' "$config")
  local nuclei_severity=$(yq e '.nuclei.severity' "$config")
  local nuclei_rate_limit=$(yq e '.nuclei.rate_limit' "$config")
  local nuclei_timeout=$(yq e '.nuclei.timeout' "$config")

  # Moda göre ayarları uyarla
  case "$mode" in
    "quick")
      nuclei_severity="high,critical"
      nuclei_rate_limit=300
      ;;
    "deep")
      nuclei_severity="info,low,medium,high,critical"
      ;;
  esac

  local output_file="$output/scans/nuclei_scan.json"

  # Nuclei komutunu oluştur ve çalıştır
  local nuclei_cmd="nuclei -u $target -severity $nuclei_severity -rate-limit $nuclei_rate_limit \
  -timeout $nuclei_timeout -t $nuclei_templates -json -o $output_file"
  echo -e "${YELLOW}[COMMAND] $nuclei_cmd${NC}"
  
  if eval "$nuclei_cmd"; then
    echo -e "${GREEN}[+] Nuclei scan completed successfully${NC}"
    
    # JSON'ı HTML raporuna dönüştür
    jq -r '.[] | "\(.templateID): \(.info.severity) - \(.info.name)\nDescription: \(.info.description)\nReference: \(.info.reference)\n\n"' \
    "$output_file" > "$output/reports/nuclei_scan.txt" || \
    echo -e "${RED}[-] Nuclei report generation failed${NC}"
  else
    error_exit "Nuclei scan failed"
  fi
}
