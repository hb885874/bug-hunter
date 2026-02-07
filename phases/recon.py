import subprocess
import shutil
import os
from datetime import datetime
from typing import List, Optional
from rich.progress import Progress

from config import CONFIG
from .analysis import (
    normalize_hosts,
    cluster_hosts,
    extract_live_urls,
    extract_tech_fingerprints,
    extract_katana_params,
)

BASE_ARTIFACT_DIR = "artifacts"


def sanitize(name: str) -> str:
    return name.replace(".", "_").lower()


def artifacts_exist(scan_name: str) -> bool:
    raw = os.path.join(BASE_ARTIFACT_DIR, scan_name, "raw")
    reports = os.path.join(BASE_ARTIFACT_DIR, scan_name, "reports")

    return (
        os.path.isdir(raw)
        and os.listdir(raw)
        and os.path.isdir(reports)
        and os.listdir(reports)
    )


def _binary_exists(binary: str) -> bool:
    if os.path.isabs(binary):
        return os.path.exists(binary)
    return shutil.which(binary) is not None


def _write_raw(scan_name: str, tool: str, output: str):
    raw_dir = os.path.join(BASE_ARTIFACT_DIR, scan_name, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    fname = f"{tool}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}.txt"
    path = os.path.join(raw_dir, fname)

    with open(path, "w", encoding="utf-8") as f:
        f.write(output or "")

    return path


def run_tool(
    cmd: List[str],
    scan_name: str,
    tool_name: str,
    timeout: int = 180,
    stdin: Optional[str] = None,
):
    binary = cmd[0]

    if not _binary_exists(binary):
        msg = f"{binary} not found; skipping {tool_name}"
        return {"ok": False, "output": msg}

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

    output = []
    for line in proc.stdout:
        print(f"[{tool_name}] {line}", end="")
        output.append(line)

    proc.wait(timeout=timeout)

    joined = "".join(output)
    _write_raw(scan_name, tool_name, joined)

    return {"ok": True, "output": joined}


def run_recon(scope):
    domain = scope["domain"]
    focus = scope.get("focus_subdomain")

    scan_name = sanitize(domain)

    if CONFIG["SKIP_RECON_IF_ARTIFACTS_EXIST"] and artifacts_exist(scan_name):
        print(f"[Recon] Skipping recon for {domain} (artifacts exist)")
        return {"skipped": True}

    print(f"[Recon] Running recon for {domain}")

    HTTPX_BIN = r"C:\Users\parve\go\bin\httpx.exe"
    results = {}

    with Progress() as progress:
        task = progress.add_task("[cyan]Recon pipeline", total=4)

        subfinder = run_tool(
            ["subfinder", "-silent", "-d", domain],
            scan_name,
            "subfinder",
        )

        amass = run_tool(
            ["amass", "enum", "-passive", "-d", domain],
            scan_name,
            "amass",
            timeout=240,
        )

        progress.advance(task)

        hosts = normalize_hosts([subfinder["output"], amass["output"]])

        if focus:
            hosts = "\n".join(h for h in hosts.splitlines() if h == focus)

        results["host_clusters"] = cluster_hosts(hosts)
        progress.advance(task)

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
            scan_name,
            "httpx",
            stdin=hosts,
        )

        live_urls = extract_live_urls(httpx["output"])
        results["live_urls"] = live_urls
        results["tech_fingerprint"] = extract_tech_fingerprints(httpx["output"])

        progress.advance(task)

        katana = run_tool(
            ["katana", "-silent"],
            scan_name,
            "katana",
            stdin="\n".join(live_urls),
            timeout=300,
        )

        results["params"] = extract_katana_params(katana["output"])
        progress.advance(task)

    return results
