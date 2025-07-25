#!/bin/bash

# Sürüm bilgisi
VERSION="1.0.0"

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Yardım mesajı
show_help() {
  echo -e "${YELLOW}Advanced Security Scanner ${VERSION}${NC}"
  echo "Usage: $0 [options] -t <target>"
  echo ""
  echo "Options:"
  echo "  -t, --target    Target to scan (URL or IP)"
  echo "  -m, --mode      Scan mode (quick, standard, deep)"
  echo "  -o, --output    Output directory"
  echo "  -c, --config    Config file path"
  echo "  -h, --help      Show this help message"
  exit 0
}

# Hata mesajı
error_exit() {
  echo -e "${RED}[ERROR] $1${NC}" >&2
  exit 1
}

# Bağımlılık kontrolü
check_dependencies() {
  local dependencies=("nmap" "nuclei" "zap-cli" "jq")
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      error_exit "$dep not found! Please install it first."
    fi
  done
}

# Ana fonksiyon
main() {
  # Varsayılan değerler
  local target=""
  local mode="standard"
  local output="./outputs"
  local config="./config/scanner-config.yaml"

  # Argümanları parse et
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target)
        target="$2"
        shift 2
        ;;
      -m|--mode)
        mode="$2"
        shift 2
        ;;
      -o|--output)
        output="$2"
        shift 2
        ;;
      -c|--config)
        config="$2"
        shift 2
        ;;
      -h|--help)
        show_help
        ;;
      *)
        error_exit "Unknown option: $1"
        ;;
    esac
  done

  # Hedef kontrolü
  if [ -z "$target" ]; then
    error_exit "Target is required!"
  fi

  # Bağımlılık kontrolü
  check_dependencies

  # Çıktı dizinini oluştur
  mkdir -p "$output/scans"
  mkdir -p "$output/reports"

  echo -e "${GREEN}[+] Starting Advanced Security Scanner v${VERSION}${NC}"
  echo -e "${YELLOW}[*] Target: $target${NC}"
  echo -e "${YELLOW}[*] Mode: $mode${NC}"
  echo -e "${YELLOW}[*] Output Directory: $output${NC}"

  # Modülleri çalıştır
  source ./scripts/nmap_scanner.sh
  run_nmap_scan "$target" "$output" "$config" "$mode"

  source ./scripts/nuclei_scanner.sh
  run_nuclei_scan "$target" "$output" "$config" "$mode"

  source ./scripts/zap_scanner.sh
  run_zap_scan "$target" "$output" "$config" "$mode"

  # Rapor oluştur
  source ./scripts/report_generator.sh
  generate_report "$output"

  echo -e "${GREEN}[+] Scan completed successfully!${NC}"
  echo -e "${GREEN}[+] Reports are available in: $output/reports${NC}"
}

main "$@"
