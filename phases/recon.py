import subprocess
import shutil
import os
from datetime import datetime
from typing import List, Optional
from rich.progress import Progress


ARTIFACT_DIR = "artifacts/raw"


def _write_raw(domain: str, tool: str, output: str) -> Optional[str]:
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
    stream: bool = True
):
    binary = cmd[0]

    if not _binary_exists(binary):
        msg = f"{binary} not found; skipping {tool_name}"
        return {
            "ok": False,
            "output": msg,
            "raw_file": _write_raw(domain, tool_name, msg),
        }

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
        return {
            "ok": False,
            "output": msg,
            "raw_file": _write_raw(domain, tool_name, msg),
        }


def _normalize_hosts(outputs: List[str]) -> str:
    hosts = set()
    for out in outputs:
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.add(line.lower())
    return "\n".join(sorted(hosts))


def run_recon(scope):
    domain = scope["domain"]
    print(f"\n[Recon] Starting reconnaissance for {domain}\n")

    HTTPX_BIN = r"C:\Users\parve\go\bin\httpx.exe"

    results = {}

    with Progress() as progress:
        task = progress.add_task("[cyan]Recon pipeline", total=4)

        # 1️⃣ Subdomain discovery
        subfinder = run_tool(
            ["subfinder", "-silent", "-d", domain],
            domain,
            "subfinder",
        )
        results["subfinder"] = subfinder
        progress.advance(task)

        amass = run_tool(
            ["amass", "enum", "-passive", "-d", domain],
            domain,
            "amass",
            timeout=240,
        )
        results["amass"] = amass
        progress.advance(task)

        # 2️⃣ Normalize hosts
        host_list = _normalize_hosts([
            subfinder["output"],
            amass["output"],
        ])

        # 3️⃣ Live host detection (httpx)
        httpx = run_tool(
            [
                HTTPX_BIN,
                "-silent",
                "-status-code",
                "-title",
                "-follow-redirects",
                "-no-color",
            ],
            domain,
            "httpx",
            stdin=host_list,
        )
        results["httpx"] = httpx
        progress.advance(task)

        # Extract only live URLs for crawling
        live_urls = "\n".join(
            line.split()[0]
            for line in httpx["output"].splitlines()
            if line.startswith("http")
        )

        # 4️⃣ Crawl only live hosts
        katana = run_tool(
            ["katana", "-silent"],
            domain,
            "katana",
            stdin=live_urls,
            timeout=300,
        )
        results["katana"] = katana
        progress.advance(task)

    print("\n[Recon] Pipeline completed\n")
    return results
