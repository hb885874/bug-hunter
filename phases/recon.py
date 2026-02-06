import subprocess
import shutil
import os
from datetime import datetime
from typing import List, Optional
from rich.progress import Progress

from .analysis import (
    normalize_hosts,
    cluster_hosts,
    extract_live_urls,
    extract_tech_fingerprints,
    extract_katana_params,
)

# Base artifacts folder
ARTIFACTS_BASE = "artifacts"


def _write_raw(scan_name: str, domain: str, tool: str, output: str):
    """
    Writes raw output to artifacts/<scan_name>/raw/
    """
    base_dir = os.path.join(ARTIFACTS_BASE, scan_name, "raw")
    os.makedirs(base_dir, exist_ok=True)
    fname = os.path.join(base_dir, f"{domain}_{tool}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}.txt")
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(output or "")
        return fname
    except Exception:
        return None


def _binary_exists(binary: str) -> bool:
    if os.path.isabs(binary):
        return os.path.exists(binary)
    return shutil.which(binary) is not None


def scan_exists(scan_name: str) -> bool:
    """
    Returns True if both raw/ and reports/ folders exist and are non-empty
    """
    raw_dir = os.path.join(ARTIFACTS_BASE, scan_name, "raw")
    reports_dir = os.path.join(ARTIFACTS_BASE, scan_name, "reports")

    raw_exists = os.path.exists(raw_dir) and bool(os.listdir(raw_dir))
    reports_exists = os.path.exists(reports_dir) and bool(os.listdir(reports_dir))

    return raw_exists and reports_exists


def run_tool(
    cmd: List[str],
    domain: str,
    tool_name: str,
    scan_name: str,
    timeout: int = 180,
    stdin: Optional[str] = None,
    stream: bool = True,
):
    """
    Run a recon tool and write raw output to scan-specific folder
    """
    binary = cmd[0]

    if not _binary_exists(binary):
        msg = f"{binary} not found; skipping {tool_name}"
        return {"ok": False, "output": msg, "raw_file": _write_raw(scan_name, domain, tool_name, msg)}

    output_lines = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        if stdin:
            proc.stdin.write(stdin)
            proc.stdin.close()

        for line in proc.stdout:
            if stream:
                print(f"[{tool_name}] {line}", end="")
            output_lines.append(line)

        proc.wait(timeout=timeout)

        output = "".join(output_lines)
        return {
            "ok": True,
            "output": output,
            "raw_file": _write_raw(scan_name, domain, tool_name, output),
        }

    except subprocess.TimeoutExpired:
        msg = f"{tool_name} timed out after {timeout}s"
        return {"ok": False, "output": msg, "raw_file": _write_raw(scan_name, domain, tool_name, msg)}


def run_recon(scope):
    """
    scope = {
        "domain": "example.com",
        "focus_subdomain": "api.example.com",  # optional
        "scan_name": "tesla"  # optional, default = domain.replace('.', '_')
    }
    """

    domain = scope["domain"]
    focus = scope.get("focus_subdomain")
    scan_name = scope.get("scan_name", domain.replace(".", "_"))

    # Skip recon if both raw and reports exist
    if scan_exists(scan_name):
        print(f"[Recon] Raw and reports already exist for '{scan_name}'. Skipping recon phase.")
        return {"skipped": True, "message": "Recon skipped; artifacts exist."}

    print(f"\n[Recon] Target: {domain}")
    if focus:
        print(f"[Recon] Focus mode enabled → {focus}\n")

    HTTPX_BIN = r"C:\Users\parve\go\bin\httpx.exe"
    results = {}

    with Progress() as progress:
        task = progress.add_task("[cyan]Recon pipeline", total=4)

        # 1️⃣ Discovery
        subfinder = run_tool(
            ["subfinder", "-silent", "-d", domain],
            domain,
            "subfinder",
            scan_name,
        )

        amass = run_tool(
            ["amass", "enum", "-passive", "-d", domain],
            domain,
            "amass",
            scan_name,
            timeout=240,
        )

        progress.advance(task)

        # 2️⃣ Normalize + optional scope narrowing
        hosts = normalize_hosts([subfinder["output"], amass["output"]])

        if focus:
            hosts = "\n".join(h for h in hosts.splitlines() if h == focus)

        clusters = cluster_hosts(hosts)
        results["host_clusters"] = clusters

        progress.advance(task)

        # 3️⃣ Live detection + tech fingerprinting
        httpx = run_tool(
            [
                HTTPX_BIN,
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
                "-no-color",
            ],
            domain,
            "httpx",
            scan_name,
            stdin=hosts,
        )
        results["httpx_raw"] = httpx

        live_urls = extract_live_urls(httpx["output"])
        tech = extract_tech_fingerprints(httpx["output"])

        results["live_urls"] = live_urls
        results["tech_fingerprint"] = tech

        progress.advance(task)

        # 4️⃣ Crawl + parameter extraction
        katana = run_tool(
            ["katana", "-silent"],
            domain,
            "katana",
            scan_name,
            stdin="\n".join(live_urls),
            timeout=300,
        )

        params = extract_katana_params(katana["output"])

        results["katana_raw"] = katana
        results["params"] = params

        progress.advance(task)

    print("\n[Recon] Pipeline completed\n")
    return results
