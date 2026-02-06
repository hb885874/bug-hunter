import subprocess
from typing import Optional

class LocalLLM:
    """
    Simple wrapper for a local LLM.
    Calls a CLI or Python module to generate text from a prompt.
    """
    def __init__(self, model_path: str, cmd_template: Optional[list] = None, timeout: int = 120):
        self.model_path = model_path
        self.timeout = timeout
        # Default CLI call
        self.cmd_template = cmd_template or ["text-generation-cli", "--model", self.model_path]

    def __call__(self, prompt: str) -> str:
        try:
            proc = subprocess.run(
                self.cmd_template,
                input=prompt,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=self.timeout
            )
            return proc.stdout
        except Exception as e:
            return f"[Local LLM error]: {e}"
