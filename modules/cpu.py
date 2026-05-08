"""§4 CPU Investigation"""
import re


def investigate(ts, pid):
    if ts.over_budget():
        return
    print(f"\n── §4 CPU Investigation — PID {pid} ──\n")

    c = ts.cfg
    cores = ts.report.cores or 1
    cpu_pct = ts.report.process_cpu
    per_core = cpu_pct / cores
    print(f"  Process %CPU: {cpu_pct:.1f}% on {cores} cores ({per_core:.1f}% of total capacity)")

    pn = ts._pn(pid)
    if cpu_pct >= c["cpu_process_critical_pct"]:
        ts._finding("cpu", "critical",
                     f"{pn} consuming {cpu_pct:.1f}% CPU — saturating ~{cpu_pct/100:.0f} core(s)")
    elif cpu_pct >= c["cpu_process_high_pct"]:
        ts._finding("cpu", "warning", f"{pn} elevated CPU at {cpu_pct:.1f}%")

    r1 = ts.report.load_1m / cores if cores else 0
    r15 = ts.report.load_15m / cores if cores else 0
    if r1 > r15 * c["cpu_load_spike_multiplier"]:
        ts._finding("cpu", "info", "Load spike is recent (1m >> 15m) — issue started within last few minutes")
    elif abs(r1 - r15) / max(r15, 0.01) < c["cpu_load_stable_tolerance"]:
        ts._finding("cpu", "info", "Load is stable — CPU pressure may be chronic")

    lookback = c["log_lookback_minutes"]
    max_log = c["out_max_log_lines"]
    slow_to = c["slow_command_timeout_secs"]

    print("\n  Checking system logs...")
    if ts.runner.is_darwin:
        out = ts.runner.run(
            f"log show --predicate 'messageType == error' --last {lookback}m "
            f"--style compact 2>/dev/null | tail -{max_log}",
            timeout=slow_to,
        )
    else:
        out = ts.runner.run(
            f"journalctl --since '{lookback} minutes ago' --priority=warning "
            f"--no-pager 2>/dev/null | tail -{max_log}"
        )
    if out.strip():
        relevant = [l for l in out.splitlines() if l.strip()]
        if relevant:
            ts._finding("cpu", "info", f"Found {len(relevant)} recent log entries (last {lookback}m)")
            for line in relevant[:5]:
                print(f"    {line[:120]}")
    else:
        print("  No recent warning/error log entries.")

    if ts.runner.is_darwin:
        out = ts.runner.run(
            f"log show --predicate 'eventMessage contains \"jettisoned\"' --last {lookback}m "
            f"--style compact 2>/dev/null | tail -5",
            timeout=slow_to,
        )
        if out.strip():
            ts._finding("cpu", "warning", f"macOS memory jetsam events detected in last {lookback} minutes")
            for line in out.splitlines()[:3]:
                print(f"    {line[:120]}")
    else:
        out = ts.runner.run("dmesg -T 2>/dev/null | grep -i 'oom\\|killed process' | tail -10")
        if out.strip():
            ts._finding("cpu", "warning", "OOM killer activity detected")
            for line in out.splitlines()[:3]:
                print(f"    {line[:120]}")

    n_threads = c["out_top_thread_count"]
    print("\n  Thread breakdown:")
    if ts.runner.is_darwin:
        out = ts.runner.run(f"ps -M -p {pid} -o pid,pcpu,comm | head -{n_threads}")
    else:
        out = ts.runner.run(f"ps -p {pid} -L -o tid,%cpu,comm | sort -k2 -rn | head -{n_threads}")
    if out.strip():
        print(f"  {out.replace(chr(10), chr(10) + '  ')}")

    name = ts.report.process_name
    ts._recommend(
        f"PID {pid} ({name}) is consuming {cpu_pct:.1f}% CPU. "
        f"To profile, operator may run:  sample {pid} 5 -file /tmp/{pid}.sample  (macOS) "
        f"or  perf record -p {pid} -g -- sleep 5  (Linux). "
        f"Do NOT kill or restart the process from this agent."
    )
