
import threading
import queue
import signal
import sys
import time

from phases.scope_parser import parse_scope
from phases.recon import run_recon
from phases.reasoning import intelligent_analysis
from phases.report import generate_report


class Agent:
    def __init__(self):
        self._queue = queue.Queue()
        self._stop_event = threading.Event()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)

    def start(self):
        print("VDP Agent Extended starting. Type a domain to enqueue a scan, 'status', or 'shutdown'.")
        self._worker.start()
        self._repl()

    def stop(self):
        print("Shutting down agent...")
        self._stop_event.set()
        # Put sentinel to wake the worker
        self._queue.put(None)
        self._worker.join(timeout=5)
        print("Agent stopped.")

    def enqueue(self, scope):
        self._queue.put(scope)


    def _worker_loop(self):
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=1)
            except Exception:
                continue
            if item is None:
                break

            scope = item
            domain = scope["domain"]

            focus = scope.get("focus_subdomain")
            if focus:
                print(f"[Worker] Starting FOCUSED scan for {domain} → {focus}")
            else:
                print(f"[Worker] Starting full scan for {domain}")

            recon_data = run_recon(scope)
            findings = intelligent_analysis(scope, recon_data)
            report = generate_report(domain, findings)

            print(f"[Worker] Report generated: {report}")
            self._queue.task_done()

    def _repl(self):
        def handle_sigint(sig, frame):
            print("\nReceived interrupt, shutting down...")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, handle_sigint)

        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                line = "shutdown"

            if not line:
                continue

            if line.lower() in ("exit", "quit", "shutdown"):
                self.stop()
                break

            if line.lower() == "status":
                qsize = self._queue.qsize()
                print(f"Queue size: {qsize}")
                continue

            # Accept commands like: scan example.com or just example.com
            parts = line.split()

            if parts[0].lower() == "scan":
                parts = parts[1:]

            domain = parts[0]
            focus = None

            if "--focus" in parts:
                idx = parts.index("--focus")
                if idx + 1 < len(parts):
                    focus = parts[idx + 1]

            scope = {"domain": domain}
            if focus:
                scope["focus_subdomain"] = focus
                print(f"[Agent] Enqueued focused scan: {domain} → {focus}")
            else:
                print(f"[Agent] Enqueued full scan: {domain}")

            self.enqueue(scope)



def main():
    agent = Agent()
    agent.start()


if __name__ == "__main__":
    main()
