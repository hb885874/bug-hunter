from .llm_local import LocalLLM
import json

llm = LocalLLM(model="codestral:22b")

def intelligent_analysis(scope: dict, recon: dict) -> dict:
    domain = scope["domain"]

    prompt = f"""
You are a senior application security researcher.

Context:
Target domain: {domain}

Recon summary (structured, partial):
{json.dumps(recon, indent=2)}

Tasks:
1. Identify interesting hosts (prod vs dev vs api)
2. Highlight risky patterns or misconfigurations
3. Suggest manual validation ideas
4. DO NOT invent vulnerabilities
5. Be concise and structured

Return your answer in this JSON format:
{{
  "interesting_hosts": [],
  "risk_observations": [],
  "manual_test_ideas": [],
  "confidence_notes": ""
}}
"""

    response = llm.generate(prompt)

    return {
        "domain": domain,
        "local_llm_analysis": response,
    }
