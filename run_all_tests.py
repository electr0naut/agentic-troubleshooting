"""
Test runner — launches each dummy process and runs the troubleshooter against it.

Each scenario demonstrates a different investigation branch:
  1. CPU saturation      (auto-detected via high %CPU)
  2. Memory pressure     (symptom-hinted, 512 MB allocation)
  3. I/O pressure        (symptom-hinted, fsync loop)
  4. FD exhaustion       (auto-detected via FD ratio)
  5. Network congestion  (auto + symptom, slow-consumer pattern)
"""
import atexit
import os
import signal
import subprocess
import sys
import time

PYTHON = sys.executable
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

SCENARIOS = [
    {
        "name": "CPU Saturation",
        "dummy_cmd": [PYTHON, "cpu_burner.py"],
        "ts_extra_args": [],
        "warmup": 3,
    },
    {
        "name": "Memory Pressure",
        "dummy_cmd": [PYTHON, "mem_hog.py", "--mb", "512"],
        "ts_extra_args": ["--symptom", "high memory"],
        "warmup": 3,
    },
    {
        "name": "I/O Pressure",
        "dummy_cmd": [PYTHON, "io_slowpoke.py"],
        "ts_extra_args": ["--symptom", "slow disk io"],
        "warmup": 2,
    },
    {
        "name": "FD Exhaustion",
        "dummy_cmd": [PYTHON, "fd_leaker.py", "--soft-limit", "256", "--target-ratio", "0.85"],
        "ts_extra_args": [],
        "warmup": 2,
    },
    {
        "name": "Network Congestion",
        "dummy_cmd": [PYTHON, "net_congestion.py", "--connections", "20"],
        "ts_extra_args": ["--symptom", "network congestion"],
        "warmup": 3,
    },
]

live_procs = []


def cleanup():
    for p in live_procs:
        try:
            p.terminate()
            p.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                p.kill()
            except ProcessLookupError:
                pass


atexit.register(cleanup)


def run_scenario(scenario):
    name = scenario["name"]
    print(f"\n{'#'*60}")
    print(f"  SCENARIO: {name}")
    print(f"{'#'*60}\n")

    # Launch dummy
    dummy = subprocess.Popen(
        scenario["dummy_cmd"],
        cwd=PROJECT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    live_procs.append(dummy)
    pid = dummy.pid
    print(f"  Launched dummy PID {pid}: {' '.join(scenario['dummy_cmd'])}")

    # Wait for dummy output (PID announcement) and warmup
    time.sleep(scenario["warmup"])

    # Read any dummy stdout
    try:
        dummy.stdout.flush()
    except (ValueError, OSError):
        pass

    # Run troubleshooter
    ts_cmd = [
        PYTHON, "troubleshooter.py",
        "--pid", str(pid),
    ] + scenario["ts_extra_args"]

    print(f"  Running troubleshooter: {' '.join(ts_cmd)}\n")
    ts_result = subprocess.run(ts_cmd, cwd=PROJECT_DIR, capture_output=True, text=True, timeout=120)
    print(ts_result.stdout)
    if ts_result.stderr:
        print(f"  [stderr] {ts_result.stderr}", file=sys.stderr)

    # Stop dummy
    dummy.terminate()
    try:
        dummy.wait(timeout=5)
    except subprocess.TimeoutExpired:
        dummy.kill()
    live_procs.remove(dummy)

    return ts_result.returncode == 0


def main():
    print(f"{'='*60}")
    print(f"  AGENTIC TROUBLESHOOTER — FULL TEST SUITE")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Python: {PYTHON}")
    print(f"{'='*60}")

    results = {}
    for scenario in SCENARIOS:
        try:
            ok = run_scenario(scenario)
            results[scenario["name"]] = "PASS" if ok else "FAIL"
        except KeyboardInterrupt:
            print("\n  Interrupted — cleaning up...")
            cleanup()
            sys.exit(1)
        except Exception as e:
            results[scenario["name"]] = f"ERROR: {e}"

    print(f"\n{'='*60}")
    print(f"  TEST RESULTS SUMMARY")
    print(f"{'='*60}")
    for name, result in results.items():
        print(f"    {name:.<30} {result}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
