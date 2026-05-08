"""§5 Memory Investigation"""
import re
import time
from datetime import datetime


def investigate(ts, pid):
    if ts.over_budget():
        return
    print(f"\n── §5 Memory Investigation — PID {pid} ──\n")

    c = ts.cfg
    out = ts.runner.run(f"ps -p {pid} -o pid,rss,vsz,%mem,comm")
    print(f"  {out}")

    rss_out = ts.runner.run(f"ps -p {pid} -o rss=")
    vsz_out = ts.runner.run(f"ps -p {pid} -o vsz=")
    rss_mb = 0
    vsz_mb = 0
    try:
        rss_mb = int(rss_out.strip()) / 1024
    except (ValueError, AttributeError):
        pass
    try:
        vsz_mb = int(vsz_out.strip()) / 1024
    except (ValueError, AttributeError):
        pass

    pn = ts._pn(pid)
    mem_pct = ts.report.process_mem
    if mem_pct > c["mem_process_high_pct"]:
        ts._finding("memory", "critical", f"{pn} RSS: {rss_mb:.0f} MB ({mem_pct:.1f}% of system)")
    elif rss_mb > c["mem_rss_warning_mb"]:
        ts._finding("memory", "warning", f"{pn} RSS: {rss_mb:.0f} MB ({mem_pct:.1f}% of system)")
    else:
        ts._finding("memory", "info", f"{pn} RSS: {rss_mb:.0f} MB ({mem_pct:.1f}% of system)")

    if vsz_mb > rss_mb * c["mem_vsz_rss_ratio_warning"] and vsz_mb > c["mem_vsz_absolute_warning_mb"]:
        ts._finding("memory", "info",
                     f"{pn} VSZ ({vsz_mb:.0f} MB) is {vsz_mb/max(rss_mb,1):.0f}x RSS — large virtual reservation")

    if ts.runner.is_darwin:
        print("\n  Memory map summary:")
        out = ts.runner.run(f"vmmap --summary {pid} 2>/dev/null | tail -8",
                            timeout=c["slow_command_timeout_secs"])
        if out.strip():
            print(f"  {out.replace(chr(10), chr(10) + '  ')}")
        else:
            print("  (vmmap not available or insufficient permissions)")

    attr_pct = c["mem_swap_attribution_pct"]
    comp_warn = c["mem_compression_warning_mb"]

    print("\n  Swap & compression check (system-wide context):")
    if ts.runner.is_darwin:
        out = ts.runner.run("sysctl vm.swapusage")
        if out:
            print(f"  {out}")
            match = re.search(r'used\s*=\s*([\d.]+)([MG])', out)
            if match:
                used_val = float(match.group(1))
                unit = match.group(2)
                used_mb = used_val * 1024 if unit == "G" else used_val
                if used_mb > 0 and mem_pct > attr_pct:
                    ts._finding("memory", "warning",
                                f"System swap in use ({used_val:.1f}{unit}) and {pn} "
                                f"is consuming {mem_pct:.1f}% of RAM — may be contributing to swap pressure")
                elif used_mb > 0:
                    ts._finding("memory", "info",
                                f"System swap in use ({used_val:.1f}{unit}) but {pn} "
                                f"is only {mem_pct:.1f}% of RAM — swap is from other processes")
                else:
                    ts._finding("memory", "info", "No swap in use")

        out = ts.runner.run("vm_stat | grep compressor")
        if out:
            match = re.search(r'(\d+)', out)
            if match:
                page_size_out = ts.runner.run("pagesize")
                page_size = int(page_size_out.strip()) if page_size_out.strip().isdigit() else 16384
                compressed_mb = int(match.group(1)) * page_size / (1024 * 1024)
                print(f"  Compressed memory: {compressed_mb:.0f} MB")
                if compressed_mb > comp_warn and mem_pct > attr_pct:
                    ts._finding("memory", "warning",
                                f"Heavy memory compression ({compressed_mb:.0f} MB) and {pn} "
                                f"is a significant consumer ({mem_pct:.1f}%) — may be contributing")
                elif compressed_mb > comp_warn:
                    ts._finding("memory", "info",
                                f"System memory compression active ({compressed_mb:.0f} MB) — "
                                f"not attributed to {pn} ({mem_pct:.1f}% of RAM)")
    else:
        out = ts.runner.run(f"grep -i swap /proc/{pid}/status 2>/dev/null")
        if out:
            print(f"  {out}")
            swap_match = re.search(r'VmSwap:\s+(\d+)\s+kB', out)
            if swap_match:
                proc_swap_mb = int(swap_match.group(1)) / 1024
                if proc_swap_mb > c["mem_proc_swap_warning_mb"]:
                    ts._finding("memory", "warning",
                                f"{pn} has {proc_swap_mb:.0f} MB swapped out")
                elif proc_swap_mb > 0:
                    ts._finding("memory", "info",
                                f"{pn} has {proc_swap_mb:.0f} MB swapped out")
        out = ts.runner.run("cat /proc/meminfo 2>/dev/null | grep -E 'SwapTotal|SwapFree'")
        if out:
            print(f"  {out}")

    sample_count = c["mem_rss_sample_count"]
    sample_interval = c["mem_rss_sample_interval"]
    print(f"\n  RSS growth check ({sample_count} samples, {sample_interval}s apart):")
    samples = []
    for i in range(sample_count):
        rss = ts.runner.run(f"ps -p {pid} -o rss=")
        try:
            samples.append(int(rss.strip()))
        except (ValueError, AttributeError):
            break
        stamp = datetime.now().strftime("%H:%M:%S")
        print(f"    {stamp}  RSS = {samples[-1]/1024:.1f} MB")
        if i < sample_count - 1:
            time.sleep(sample_interval)

    if len(samples) >= 2:
        growth = samples[-1] - samples[0]
        growth_pct = (growth / max(samples[0], 1)) * 100
        if growth_pct > c["mem_rss_growth_warning_pct"]:
            ts._finding("memory", "warning",
                         f"{pn} RSS grew {growth/1024:.1f} MB ({growth_pct:.1f}%) over "
                         f"{(len(samples)-1)*sample_interval}s — possible leak")
        elif growth_pct > 0:
            ts._finding("memory", "info", f"{pn} RSS grew slightly: +{growth/1024:.1f} MB ({growth_pct:.1f}%)")
        else:
            ts._finding("memory", "info", f"{pn} RSS stable during observation window")

    if ts.runner.is_darwin:
        out = ts.runner.run("memory_pressure 2>/dev/null | head -5")
        if out:
            print(f"\n  Memory pressure:\n  {out.replace(chr(10), chr(10) + '  ')}")
            if "critical" in out.lower():
                ts._finding("memory", "critical", "System under CRITICAL memory pressure")
            elif "warn" in out.lower():
                ts._finding("memory", "warning", "System under memory pressure (warning level)")

    ts._recommend(
        f"PID {pid} using {rss_mb:.0f} MB RSS ({mem_pct:.1f}% of system memory). "
        f"To monitor for leak, operator may run:  "
        f"watch -n5 'ps -p {pid} -o rss=,vsz=,%mem='  "
        f"Do NOT kill or restart the process from this agent."
    )
