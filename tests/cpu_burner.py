"""Dummy process that consumes ~100% of one CPU core."""
import sys
import os
import signal

def main():
    print(f"CPU burner started — PID {os.getpid()}", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    x = 0.0
    while True:
        x += 1.0
        x *= 0.999999

if __name__ == "__main__":
    main()
