# config.py

CONFIG = {
    # LLM
    "USE_LOCAL_LLM": True,
    "LOCAL_LLM_MODEL": "deepseek-coder:1.3b",
    "OLLAMA_URL": "http://localhost:11434/api/generate",

    # Recon
    "SKIP_RECON_IF_ARTIFACTS_EXIST": True,
}
