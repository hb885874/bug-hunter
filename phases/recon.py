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


ARTIFACT_DIR = "artifacts/raw"


def _write_raw(domain: str, tool: str, output: str):
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    fname = f"{ARTIFACT_DIR}/{domain}_{tool}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}.txt"
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


def run_tool(
    cmd: List[str],
    domain: str,
    tool_name: str,
    timeout: int = 180,
    stdin: Optional[str] = None,
    stream: bool = True,
):
    binary = cmd[0]

    if not _binary_exists(binary):
        msg = f"{binary} not found; skipping {tool_name}"
        return {"ok": False, "output": msg, "raw_file": _write_raw(domain, tool_name, msg)}

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
            "raw_file": _write_raw(domain, tool_name, output),
        }

    except subprocess.TimeoutExpired:
        msg = f"{tool_name} timed out after {timeout}s"
        return {"ok": False, "output": msg, "raw_file": _write_raw(domain, tool_name, msg)}


def run_recon(scope):
    """
    scope = {
        "domain": "example.com",
        "focus_subdomain": "api.example.com"  # optional
    }
    """

    domain = scope["domain"]
    focus = scope.get("focus_subdomain")

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
        )

        amass = run_tool(
            ["amass", "enum", "-passive", "-d", domain],
            domain,
            "amass",
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
            stdin="\n".join(live_urls),
            timeout=300,
        )

        params = extract_katana_params(katana["output"])

        results["katana_raw"] = katana
        results["params"] = params

        progress.advance(task)

    print("\n[Recon] Pipeline completed\n")
    return results
