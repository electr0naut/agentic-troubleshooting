"""§6 I/O Investigation"""
import os
import re


def investigate(ts, pid):
    if ts.over_budget():
        return
    print(f"\n── §6 I/O Investigation — PID {pid} ──\n")

    c = ts.cfg
    pn = ts._pn(pid)
    state = ts.report.process_state
    if state.startswith("D") or state.startswith("U"):
        ts._finding("io", "warning", f"{pn} in uninterruptible sleep ({state}) — likely waiting on I/O")
    else:
        ts._finding("io", "info", f"{pn} state is '{state}' — investigating I/O indicators")

    print("  Disk I/O stats:")
    if ts.runner.is_darwin:
        out = ts.runner.run("iostat -d -c 3 -w 1 2>/dev/null")
        if out:
            print(f"  {out.replace(chr(10), chr(10) + '  ')}")
    else:
        max_log = c["out_max_log_lines"]
        out = ts.runner.run(f"iostat -x 1 3 2>/dev/null | tail -{max_log}")
        if out:
            print(f"  {out.replace(chr(10), chr(10) + '  ')}")
        proc_io = ts.runner.run(f"cat /proc/{pid}/io 2>/dev/null")
        if proc_io:
            print(f"\n  Process I/O counters:\n  {proc_io.replace(chr(10), chr(10) + '  ')}")

    max_reg = c["out_max_reg_files"]
    print("\n  Open disk files:")
    out = ts.runner.run(f"lsof -p {pid} 2>/dev/null | grep REG | head -{max_reg}")
    reg_count = 0
    file_dirs = set()
    if out.strip():
        lines = [l for l in out.splitlines() if l.strip()]
        reg_count = len(lines)
        print(f"  {out.replace(chr(10), chr(10) + '  ')}")
        for line in lines:
            parts = line.split()
            if len(parts) >= 9:
                file_dirs.add(os.path.dirname(parts[8]))
    else:
        print("  (no regular files open)")

    total_fds = ts.report.open_files
    if total_fds > 0 and reg_count > 0:
        reg_ratio = reg_count / total_fds
        ts._finding("io", "info",
                     f"{pn} has {reg_count} regular file FDs out of {total_fds} total ({reg_ratio:.0%})")
        if reg_ratio > c["io_reg_fd_ratio_warning"] and reg_count > c["io_reg_fd_count_min"]:
            ts._finding("io", "warning",
                         f"{pn} has high proportion of disk file FDs — I/O heavy")

    if file_dirs:
        print("\n  Filesystem usage for open file locations:")
        for d in sorted(file_dirs)[:5]:
            out = ts.runner.run(f"df -h {d} 2>/dev/null | tail -1")
            if out:
                print(f"    {out}")
                match = re.search(r'(\d+)%', out)
                if match and int(match.group(1)) >= c["io_disk_usage_critical_pct"]:
                    ts._finding("io", "critical",
                                f"Filesystem containing {d} is {match.group(1)}% full")

    cpu_pct = ts.report.process_cpu
    cputime_out = ts.runner.run(f"ps -p {pid} -o time=")
    if cputime_out.strip():
        print(f"\n  Process cumulative CPU time: {cputime_out.strip()}")
        parts = cputime_out.strip().split(":")
        try:
            if len(parts) == 3:
                total_secs = int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
            elif len(parts) == 2:
                total_secs = int(parts[0]) * 60 + float(parts[1])
            else:
                total_secs = 0
            if cpu_pct < c["io_iobound_cpu_max_pct"] and total_secs > c["io_iobound_cumtime_secs"]:
                ts._finding("io", "warning",
                             f"{pn} low current CPU ({cpu_pct:.1f}%) but {total_secs:.0f}s cumulative — "
                             f"spends significant time waiting (likely I/O)")
        except (ValueError, IndexError):
            pass

    lookback = c["log_lookback_minutes"]
    slow_to = c["slow_command_timeout_secs"]
    print("\n  Checking for I/O errors in system logs...")
    if ts.runner.is_darwin:
        out = ts.runner.run(
            f"log show --predicate 'sender == \"kernel\" AND messageType == error' --last {lookback}m "
            f"--style compact 2>/dev/null | grep -iE 'disk|io|storage|nand' | tail -5",
            timeout=slow_to,
        )
    else:
        out = ts.runner.run("dmesg -T 2>/dev/null | grep -iE 'error.*sd|i/o error|bad sector' | tail -10")
    if out.strip():
        ts._finding("io", "warning", "I/O related errors found in system logs")
        for line in out.splitlines()[:3]:
            print(f"    {line[:120]}")
    else:
        print("  No I/O errors found in recent logs.")

    ts._recommend(
        f"PID {pid} shows I/O activity. Operator should investigate storage health. "
        f"To inspect further:  iostat -d -c 10 -w 1  (macOS) or  iostat -x 1 5  (Linux). "
        f"Check  lsof -p {pid}  for file access patterns. "
        f"Do NOT kill or restart the process from this agent."
    )
