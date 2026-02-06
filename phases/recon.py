
import subprocess
import shutil
import os
from datetime import datetime


def _write_raw(domain, tool, output):
    os.makedirs("artifacts/raw", exist_ok=True)
    fname = f"artifacts/raw/{domain}_{tool}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}.txt"
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(output or "")
    except Exception:
        fname = None
    return fname


def run_tool(cmd, domain, tool_name, timeout=180):
    # Check if binary exists
    binary = cmd[0]
    if shutil.which(binary) is None:
        msg = f"{binary} not found on PATH; skipping {tool_name}."
        fname = _write_raw(domain, tool_name, msg)
        return {"ok": False, "output": msg, "raw_file": fname}

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        out = proc.stdout or ""
        fname = _write_raw(domain, tool_name, out)
        return {"ok": True, "output": out, "raw_file": fname}
    except subprocess.TimeoutExpired:
        msg = f"{tool_name} timed out after {timeout}s"
        fname = _write_raw(domain, tool_name, msg)
        return {"ok": False, "output": msg, "raw_file": fname}
    except Exception as e:
        msg = f"{tool_name} failed: {e}"
        fname = _write_raw(domain, tool_name, msg)
        return {"ok": False, "output": msg, "raw_file": fname}


def run_recon(scope):
    domain = scope["domain"]
    print(f"[Recon] Running tool orchestration for {domain}")

    results = {}

    results["httpx"] = run_tool(["httpx", "-silent", "-title", f"https://{domain}"], domain, "httpx")
    results["subfinder"] = run_tool(["subfinder", "-silent", "-d", domain], domain, "subfinder")
    results["amass"] = run_tool(["amass", "enum", "-passive", "-d", domain], domain, "amass", timeout=240)
    results["katana"] = run_tool(["katana", "-silent", "-u", f"https://{domain}"], domain, "katana")

    return results
