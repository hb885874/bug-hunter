import requests
import json
from typing import Optional

OLLAMA_URL = "http://localhost:11434/api/generate"

class LocalLLM:
    def __init__(
        self,
        model: str = "codestral:22b",
        timeout: int = 180,
        temperature: float = 0.2,
    ):
        self.model = model
        self.timeout = timeout
        self.temperature = temperature

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
            },
        }

        try:
            r = requests.post(
                OLLAMA_URL,
                json=payload,
                timeout=self.timeout,
            )
            r.raise_for_status()
            return r.json().get("response", "")
        except Exception as e:
            return f"[LocalLLM error] {e}"
