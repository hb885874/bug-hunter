import os
import json
from typing import Dict

# -------------------------------
# LLM configuration
# -------------------------------

USE_OPENAI = False #True  # Toggle OpenAI usage for final report
OPENAI_MODEL = "gpt-4"  # Model for final report

# -------------------------------
# Initialize your LLMs
# -------------------------------

# --- Local LLM ---
# Here you plug in your local model wrapper.
# Example: a class LocalLLM with a __call__(prompt) method
# You can use llama.cpp, text-generation-webui, Mistral, etc.
# The agent will call local_llm(prompt) to get structured insights

try:
    from llm_local import LocalLLM  # <-- you need to implement/provide this
    local_llm = LocalLLM(model_path="models/ggml-model.bin")  # path to local model
except ImportError:
    print("[Warning] Local LLM wrapper not found. Please implement llm_local.py")
    local_llm = None

# --- OpenAI LLM ---
try:
    from langchain import OpenAI
    openai_llm = OpenAI(model_name=OPENAI_MODEL, temperature=0)
except ImportError:
    print("[Warning] OpenAI LLM not installed. Install langchain and openai if needed.")
    openai_llm = None

# -------------------------------
# Hybrid reasoning function
# -------------------------------

def intelligent_analysis(scope: Dict, recon_results: Dict) -> Dict:
    """
    Runs hybrid reasoning:
      1. Local LLM for structured processing
      2. Optional OpenAI for final VDP-ready report

    Args:
        scope: {"domain": "example.com", "focus_subdomain": "api.example.com"} (optional)
        recon_results: Output from run_recon()

    Returns:
        findings: dict with structured insights
    """
    domain = scope.get("domain")
    focus = scope.get("focus_subdomain")

    findings = {"domain": domain, "focus": focus}

    # ---------------------------------
    # Step 1: Local LLM processing
    # ---------------------------------
    if local_llm is None:
        findings["local_insights"] = "[Local LLM not configured]"
    else:
        local_prompt = f"""
You are a cybersecurity assistant. Analyze the following recon results:

- Host clusters
- Parameters and endpoints
- Tech fingerprinting
- Risk assessment

Recon data (JSON):
{json.dumps(recon_results, indent=2)}
"""
        local_output = local_llm(local_prompt)
        findings["local_insights"] = local_output

    # ---------------------------------
    # Step 2: Optional OpenAI summarization
    # ---------------------------------
    if USE_OPENAI:
        if openai_llm is None:
            findings["final_report"] = "[OpenAI LLM not available]"
        else:
            openai_prompt = f"""
You are a cybersecurity assistant. 
Given the processed findings from a local LLM, generate a concise, VDP-ready report:

Processed Findings:
{findings['local_insights']}
"""
            final_report = openai_llm(openai_prompt)
            findings["final_report"] = final_report

    return findings
