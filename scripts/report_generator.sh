#!/bin/bash

# Rapor oluşturma fonksiyonu
generate_report() {
  local output="$1"
  local report_file="$output/reports/final_report_$(date +%Y%m%d_%H%M%S).html"

  echo -e "\n${YELLOW}[*] Generating Final Report...${NC}"

  # HTML rapor başlığı
  cat > "$report_file" <<EOF
<!DOCTYPE html>
<html>
<head>
  <title>Advanced Security Scanner Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #2c3e50; }
    h2 { color: #3498db; border-bottom: 1px solid #eee; padding-bottom: 5px; }
    .vulnerability { margin-bottom: 15px; padding: 10px; border-radius: 5px; }
    .high { background-color: #ffdddd; border-left: 5px solid #e74c3c; }
    .medium { background-color: #fff4dd; border-left: 5px solid #f39c12; }
    .low { background-color: #ddffdd; border-left: 5px solid #2ecc71; }
    .info { background-color: #e7f5fe; border-left: 5px solid #3498db; }
    pre { background: #f4f4f4; padding: 10px; border-radius: 5px; }
  </style>
</head>
<body>
  <h1>Advanced Security Scanner Report</h1>
  <p>Generated on: $(date)</p>
EOF

  # Nmap sonuçlarını ekle
  if [ -f "$output/reports/nmap_scan.html" ]; then
    echo "<h2>Nmap Scan Results</h2>" >> "$report_file"
    cat "$output/reports/nmap_scan.html" >> "$report_file"
  fi

  # Nuclei sonuçlarını ekle
  if [ -f "$output/scans/nuclei_scan.json" ]; then
    echo "<h2>Nuclei Scan Results</h2>" >> "$report_file"
    jq -r '.[] | 
      "<div class=\"vulnerability \(.info.severity)\">" +
      "<h3>\(.info.name) (Severity: \(.info.severity))</h3>" +
      "<p>Template ID: \(.templateID)</p>" +
      "<p>Description: \(.info.description)</p>" +
      "<p>Reference: \(.info.reference)</p>" +
      "<pre>Matched at: \(.matched-at)</pre>" +
      "</div>"
    ' "$output/scans/nuclei_scan.json" >> "$report_file"
  fi

  # ZAP sonuçlarını ekle
  if [ -f "$output/scans/zap_scan.json" ]; then
    echo "<h2>ZAP Scan Results</h2>" >> "$report_file"
    jq -r '.[] | 
      "<div class=\"vulnerability \(.risk)\">" +
      "<h3>\(.name) (Risk: \(.risk))</h3>" +
      "<p>Description: \(.description)</p>" +
      "<p>Solution: \(.solution)</p>" +
      "<p>Reference: \(.reference)</p>" +
      "</div>"
    ' "$output/scans/zap_scan.json" >> "$report_file"
  fi

  # HTML rapor kapatma
  cat >> "$report_file" <<EOF
</body>
</html>
EOF

  echo -e "${GREEN}[+] Final report generated: $report_file${NC}"
}
