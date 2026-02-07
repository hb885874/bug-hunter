import os
import json
from datetime import datetime


def sanitize(name: str) -> str:
    return name.replace(".", "_").lower()


def generate_report(domain: str, findings: dict):
    scan_name = sanitize(domain)
    report_dir = os.path.join("artifacts", scan_name, "reports")
    os.makedirs(report_dir, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")

    json_path = os.path.join(report_dir, f"report_{ts}.json")
    md_path = os.path.join(report_dir, f"report_{ts}.md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Recon Report: {domain}\n\n")
        f.write("```json\n")
        f.write(json.dumps(findings, indent=2))
        f.write("\n```")

    return md_path
