#!/bin/bash

# Nmap tarama fonksiyonu
run_nmap_scan() {
  local target="$1"
  local output="$2"
  local config="$3"
  local mode="$4"

  echo -e "\n${YELLOW}[*] Starting Nmap Scan...${NC}"

  # Config dosyasından ayarları oku
  local nmap_ports=$(yq e '.nmap.ports' "$config")
  local nmap_scripts=$(yq e '.nmap.scripts' "$config")
  local nmap_options=$(yq e '.nmap.options' "$config")

  # Moda göre ayarları uyarla
  case "$mode" in
    "quick")
      nmap_ports="1-1024"
      nmap_options="-T4 --open"
      ;;
    "deep")
      nmap_options+=" -A -p-"
      ;;
  esac

  local output_file="$output/scans/nmap_scan.xml"

  # Nmap komutunu oluştur ve çalıştır
  local nmap_cmd="nmap $nmap_options --script $nmap_scripts -p $nmap_ports -oX $output_file $target"
  echo -e "${YELLOW}[COMMAND] $nmap_cmd${NC}"
  
  if eval "$nmap_cmd"; then
    echo -e "${GREEN}[+] Nmap scan completed successfully${NC}"
    
    # XML'i HTML'e dönüştür
    xsltproc "$output_file" -o "$output/reports/nmap_scan.html" 2>/dev/null || \
    echo -e "${RED}[-] XSLT conversion failed, raw XML output kept${NC}"
  else
    error_exit "Nmap scan failed"
  fi
}
