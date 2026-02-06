
import os
from datetime import datetime

def generate_report(domain, findings):
    os.makedirs("artifacts/reports", exist_ok=True)
    filename = f"artifacts/reports/{domain}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}.md"

    with open(filename, "w") as f:
        f.write(f"# Security Findings for {domain}\n\n")

        f.write(f"Generated: {datetime.utcnow().isoformat()} UTC\n\n")

        if not findings:
            f.write("No findings identified.\n")
        else:
            for item in findings:
                f.write(f"## {item['title']}\n")
                f.write(f"Confidence: {item['confidence']}\n\n")
                f.write(f"{item['description']}\n\n")
                if item.get("evidence"):
                    f.write("**Evidence:**\n")
                    for k, v in item["evidence"].items():
                        if v:
                            f.write(f"- {k}: {v}\n")
                    f.write("\n")

    return filename
