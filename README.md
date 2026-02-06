
# VDP Agent Extended

## Features
- Orchestrates:
  - httpx
  - subfinder
  - amass (passive)
  - katana
- Intelligent interpretation layer
- Generates markdown vulnerability draft reports

## Requirements

Install ProjectDiscovery tools:

go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/projectdiscovery/katana/cmd/katana@latest

Ensure tools are in PATH.

## Run

python agent.py
