"""Dummy process that opens many file descriptors to simulate FD exhaustion."""
import argparse
import os
import resource
import signal
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--soft-limit", type=int, default=256, help="Soft FD limit to set")
    parser.add_argument("--target-ratio", type=float, default=0.85, help="Fraction of limit to fill")
    args = parser.parse_args()

    pid = os.getpid()
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    soft = min(args.soft_limit, hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    target = int(soft * args.target_ratio)

    print(f"fd_leaker started — PID {pid}, soft limit {soft}, opening {target} FDs", flush=True)

    handles = []
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    # stdin/stdout/stderr + python internals use some FDs already
    baseline = len(os.listdir(f"/dev/fd")) if os.path.exists("/dev/fd") else 5

    try:
        while len(handles) + baseline < target:
            f = open(os.devnull, "r")
            handles.append(f)
    except OSError:
        pass

    print(f"fd_leaker holding {len(handles)} extra FDs (total ~{len(handles) + baseline}) — sleeping", flush=True)
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
