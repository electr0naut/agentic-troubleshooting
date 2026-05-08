"""Dummy process that allocates and holds a configurable amount of memory."""
import argparse
import os
import signal
import sys
import time


MAX_MB = 2048


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mb", type=int, default=512, help="MB to allocate (max 2048)")
    args = parser.parse_args()

    target = min(args.mb, MAX_MB)
    print(f"mem_hog started — PID {os.getpid()}, target {target} MB", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    chunks = []
    allocated = 0
    chunk_size = 10 * 1024 * 1024  # 10 MB
    while allocated < target:
        size = min(chunk_size, (target - allocated) * 1024 * 1024)
        buf = bytearray(size)
        # Touch every page so macOS actually maps it into RSS
        for i in range(0, len(buf), 4096):
            buf[i] = 0xFF
        chunks.append(buf)
        allocated += size // (1024 * 1024)
        print(f"  allocated {allocated} MB", flush=True)

    print(f"mem_hog holding {allocated} MB — sleeping", flush=True)
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
