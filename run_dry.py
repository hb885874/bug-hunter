import time
from agent import Agent

if __name__ == "__main__":
    a = Agent()
    # start worker only (skip REPL)
    a._worker.start()
    a.enqueue("example.com")
    time.sleep(3)
    a.stop()
    print("Dry run complete")
