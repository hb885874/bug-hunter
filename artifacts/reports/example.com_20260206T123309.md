# Security Findings for example.com

Generated: 2026-02-06T12:33:09.977597 UTC

## Large External Attack Surface
Confidence: Medium

Detected 9 subdomains which may expand attack surface.

**Evidence:**
- subfinder_raw: artifacts/raw/example.com_subfinder_20260206T123309.txt
- amass_raw: artifacts/raw/example.com_amass_20260206T123309.txt

## Public Web Service Exposure
Confidence: Low

Target responds publicly. Review headers and authentication controls.

**Evidence:**
- httpx_raw: artifacts/raw/example.com_httpx_20260206T123309.txt

