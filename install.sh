#!/bin/bash

echo -e "${YELLOW}[*] Installing dependencies...${NC}"

# Temel bağımlılıklar
sudo apt update
sudo apt install -y git python3 python3-pip jq xsltproc nmap zaproxy

# YAML parser (yq) kurulumu
sudo pip3 install yq

# Nuclei kurulumu
if ! command -v nuclei &> /dev/null; then
  echo -e "${YELLOW}[*] Installing Nuclei...${NC}"
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  sudo cp ~/go/bin/nuclei /usr/local/bin/
  
  # Nuclei template'leri
  nuclei -update-templates
fi

# ZAP CLI kurulumu
if ! command -v zap-cli &> /dev/null; then
  echo -e "${YELLOW}[*] Installing ZAP CLI...${NC}"
  sudo pip3 install zapcli
fi

# Scriptlere çalıştırma izni ver
chmod +x scripts/*.sh

echo -e "${GREEN}[+] Installation completed!${NC}"
