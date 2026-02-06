
def intelligent_analysis(scope, recon_data):
    print("[Reasoning] Performing intelligent interpretation")
    findings = []

    # Subdomain exposure insight
    subfinder = recon_data.get("subfinder", {})
    amass = recon_data.get("amass", {})

    subfinder_out = subfinder.get("output", "") if isinstance(subfinder, dict) else subfinder
    amass_out = amass.get("output", "") if isinstance(amass, dict) else amass

    subdomains = set(subfinder_out.split()) | set(amass_out.split())
    if len(subdomains) > 5:
        findings.append({
            "title": "Large External Attack Surface",
            "confidence": "Medium",
            "description": f"Detected {len(subdomains)} subdomains which may expand attack surface.",
            "evidence": {
                "subfinder_raw": subfinder.get("raw_file") if isinstance(subfinder, dict) else None,
                "amass_raw": amass.get("raw_file") if isinstance(amass, dict) else None,
            }
        })

    # Web service exposure insight
    httpx = recon_data.get("httpx", {})
    httpx_out = httpx.get("output", "") if isinstance(httpx, dict) else httpx
    if httpx_out and "failed" not in httpx_out.lower():
        findings.append({
            "title": "Public Web Service Exposure",
            "confidence": "Low",
            "description": "Target responds publicly. Review headers and authentication controls.",
            "evidence": {"httpx_raw": httpx.get("raw_file") if isinstance(httpx, dict) else None}
        })

    # Endpoint discovery insight
    katana = recon_data.get("katana", {})
    katana_out = katana.get("output", "") if isinstance(katana, dict) else katana
    endpoints = katana_out.splitlines()
    if len(endpoints) > 20:
        findings.append({
            "title": "Extensive Endpoint Discovery",
            "confidence": "Medium",
            "description": f"Katana discovered {len(endpoints)} endpoints worth manual review.",
            "evidence": {"katana_raw": katana.get("raw_file") if isinstance(katana, dict) else None}
        })

    return findings
