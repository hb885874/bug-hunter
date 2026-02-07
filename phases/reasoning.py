import json
import requests
from config import CONFIG


def call_local_llm(prompt: str) -> dict:
    payload = {
        "model": CONFIG["LOCAL_LLM_MODEL"],
        "prompt": prompt,
        "stream": False,
    }

    r = requests.post(CONFIG["OLLAMA_URL"], json=payload, timeout=120)
    r.raise_for_status()

    return json.loads(r.json()["response"])


def intelligent_analysis(scope, recon_data):
    if recon_data.get("skipped"):
        return {"note": "Recon skipped, using existing artifacts"}

    if not CONFIG["USE_LOCAL_LLM"]:
        return {"note": "LLM disabled"}

    prompt = f"""
You are a security recon analyst.

Input:
- Host clusters
- Live URLs
- Technologies
- Parameters

Task:
1. Identify risky surface areas
2. Note suspicious endpoints
3. Highlight weak tech stacks
4. Output JSON only

Data:
{json.dumps(recon_data, indent=2)}
"""

    try:
        return call_local_llm(prompt)
    except Exception as e:
        return {"error": str(e)}
