"""§7 File Descriptor Investigation"""
import time
from datetime import datetime


def investigate(ts, pid):
    if ts.over_budget():
        return
    print(f"\n── §7 File Descriptor Investigation — PID {pid} ──\n")

    c = ts.cfg
    fd_count = ts.report.open_files
    fd_limit = ts.report.file_limit

    pn = ts._pn(pid)
    print(f"  Open files:  {fd_count}")
    print(f"  Soft limit:  {fd_limit}")

    if fd_limit > 0:
        ratio = fd_count / fd_limit
        print(f"  Usage:       {ratio:.0%}")

        if ratio >= 1.0:
            ts._finding("fd", "critical",
                         f"{pn} has REACHED FD limit ({fd_count}/{fd_limit}) — new opens will fail")
        elif ratio >= c["fd_usage_ratio_critical"]:
            ts._finding("fd", "critical",
                         f"{pn} at {ratio:.0%} of FD limit ({fd_count}/{fd_limit}) — approaching exhaustion")
        elif ratio >= c["fd_usage_ratio_warning"]:
            ts._finding("fd", "warning",
                         f"{pn} at {ratio:.0%} of FD limit ({fd_count}/{fd_limit})")
        else:
            ts._finding("fd", "info", f"{pn} FD usage normal ({ratio:.0%})")

    print("\n  FD type breakdown:")
    out = ts.runner.run(f"lsof -p {pid} 2>/dev/null | awk 'NR>1 {{print $5}}' | sort | uniq -c | sort -rn")
    if out:
        print(f"  {out.replace(chr(10), chr(10) + '  ')}")

    max_paths = c["out_max_file_paths"]
    print("\n  Top file paths:")
    out = ts.runner.run(
        f"lsof -p {pid} 2>/dev/null | awk 'NR>1 {{print $9}}' | sort | uniq -c | sort -rn | head -{max_paths}")
    if out:
        print(f"  {out.replace(chr(10), chr(10) + '  ')}")

    print("\n  Leak pattern analysis:")

    close_wait_out = ts.runner.run(f"lsof -p {pid} 2>/dev/null | grep -c CLOSE_WAIT")
    try:
        close_wait = int(close_wait_out.strip())
    except (ValueError, AttributeError):
        close_wait = 0
    if close_wait > c["net_close_wait_warning"]:
        ts._finding("fd", "warning",
                     f"{close_wait} sockets in CLOSE_WAIT — application not closing connections properly")
    elif close_wait > 0:
        print(f"    CLOSE_WAIT sockets: {close_wait}")

    max_dirs = c["out_max_dir_groups"]
    dir_out = ts.runner.run(
        f"lsof -p {pid} 2>/dev/null | awk 'NR>1 && $5==\"REG\" {{n=split($9,a,\"/\"); "
        f"dir=\"\"; for(i=1;i<n;i++) dir=dir\"/\"a[i]; print dir}}' | sort | uniq -c | sort -rn | head -{max_dirs}"
    )
    if dir_out.strip():
        for line in dir_out.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                count = int(parts[0])
                dirname = parts[1]
                if count > c["fd_dir_leak_threshold"]:
                    ts._finding("fd", "warning",
                                f"{count} file FDs in {dirname} — possible temp file leak")

    pipe_out = ts.runner.run(f"lsof -p {pid} 2>/dev/null | grep -cE 'PIPE|FIFO'")
    try:
        pipe_count = int(pipe_out.strip())
    except (ValueError, AttributeError):
        pipe_count = 0
    if pipe_count > c["fd_pipe_warning"]:
        ts._finding("fd", "warning",
                     f"{pipe_count} pipe/FIFO FDs — possible subprocess management issue")
    elif pipe_count > 0:
        print(f"    Pipes/FIFOs: {pipe_count}")

    fd_n = c["fd_sample_count"]
    fd_interval = c["fd_sample_interval"]
    print(f"\n  FD growth check ({fd_n} samples, {fd_interval}s apart):")
    fd_samples = []
    for i in range(fd_n):
        count_out = ts.runner.run(f"lsof -p {pid} 2>/dev/null | wc -l")
        try:
            fd_samples.append(int(count_out.strip()))
        except (ValueError, AttributeError):
            break
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"    {stamp}  FDs = {fd_samples[-1]}")
        if i < fd_n - 1:
            time.sleep(fd_interval)

    if len(fd_samples) >= 2:
        growth = fd_samples[-1] - fd_samples[0]
        if growth > c["fd_growth_active_leak"]:
            ts._finding("fd", "warning",
                         f"FD count growing: +{growth} in {(len(fd_samples)-1)*fd_interval}s — active leak")
        elif growth > 0:
            ts._finding("fd", "info", f"FD count slightly increasing: +{growth}")
        else:
            ts._finding("fd", "info", "FD count stable during observation window")

    ts._recommend(
        f"PID {pid} has {fd_count} open FDs vs limit {fd_limit}. "
        f"Operator may inspect with:  lsof -p {pid}  "
        f"To raise limit:  ulimit -n <new_limit>  (before launching the process). "
        f"Do NOT kill or restart the process from this agent."
    )
