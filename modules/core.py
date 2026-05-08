"""Troubleshooter orchestrator — decision tree from TROUBLESHOOTING_RUNBOOK.md."""
import os
import re
import time
from datetime import datetime

from .models import Finding, Report
from . import cpu, memory, disk_io, fd, network


class Troubleshooter:
    def __init__(self, runner, pid=None, symptom=None, cfg=None):
        self.runner = runner
        self.cfg = cfg or runner.cfg
        self.initial_pid = pid
        self.symptom = symptom
        self.report = Report(
            host=runner.host or "localhost",
            timestamp=datetime.now().isoformat(),
            trigger=f"PID {pid}" if pid else (symptom or "system triage"),
        )
        self.start_time = time.monotonic()

    def elapsed(self):
        return time.monotonic() - self.start_time

    def over_budget(self):
        budget = self.cfg["investigation_budget_secs"]
        if self.elapsed() > budget:
            self._finding("info", "info", f"Investigation time limit reached ({budget}s)")
            return True
        return False

    def _finding(self, category, severity, message):
        self.report.findings.append(Finding(category, severity, message))
        label = {"info": ".", "warning": "!", "critical": "!!"}[severity]
        print(f"  [{label}] {message}")

    def _recommend(self, msg):
        self.report.recommendations.append(msg)

    def _pn(self, pid=None):
        p = pid or self.report.pid
        n = self.report.process_name or "unknown"
        n = os.path.basename(n)
        return f"PID {p} ({n})"

    # ── §1: Entry Point ──────────────────────────────────────────────

    def run(self):
        print(f"\n{'='*60}")
        print(f"  TROUBLESHOOTER — {self.report.host}")
        print(f"  {self.report.timestamp}")
        print(f"  Trigger: {self.report.trigger}")
        print(f"{'='*60}\n")

        self.runner.detect_os()
        os_label = "macOS" if self.runner.is_darwin else "Linux"
        print(f"  Detected OS: {os_label}\n")

        self._gather_system_context()

        if self.initial_pid:
            self._process_deep_dive(self.initial_pid)
        else:
            pid = self._system_triage()
            if pid and not self.over_budget():
                self._process_deep_dive(pid)

        self._print_report()
        return self.report

    # ── System context ───────────────────────────────────────────────

    def _gather_system_context(self):
        print("── System Context ──\n")
        self.report.cores = self._get_cores()
        print(f"  CPU cores: {self.report.cores}")
        self._get_load()
        self._get_memory_overview()

    # ── §2: System-Wide Triage ────────────────────────────────────────

    def _system_triage(self):
        print("\n  Top processes by CPU:")
        top_procs = self._get_top_processes()
        for p in top_procs[:5]:
            print(f"    PID {p['pid']:>7}  {p['cpu']:>6.1f}%CPU  {p['mem']:>5.1f}%MEM  {p['name']}")

        d_procs = self._get_d_state_processes()
        if d_procs:
            self._finding("io", "warning", f"{len(d_procs)} process(es) in D state (uninterruptible sleep)")
            for dp in d_procs:
                print(f"    D-state: PID {dp}")

        self._interpret_load()

        if not top_procs:
            self._finding("info", "info", "No high-CPU processes found")
            return None

        cpu_high = self.cfg["cpu_process_high_pct"]
        candidate = top_procs[0]
        if candidate["cpu"] > cpu_high:
            self._finding("cpu", "warning",
                          f"Top CPU consumer: PID {candidate['pid']} ({candidate['name']}) at {candidate['cpu']:.1f}%")
            return candidate["pid"]
        elif d_procs:
            return d_procs[0]
        elif top_procs:
            self._finding("info", "info",
                          f"No process above {cpu_high}% CPU — examining top consumer PID {candidate['pid']}")
            return candidate["pid"]
        return None

    def _get_cores(self):
        if self.runner.is_darwin:
            out = self.runner.run("sysctl -n hw.logicalcpu")
        else:
            out = self.runner.run("nproc")
        try:
            return int(out.strip())
        except (ValueError, AttributeError):
            return 1

    def _get_load(self):
        out = self.runner.run("uptime")
        print(f"  uptime: {out}")
        match = re.search(r'load averages?:\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)', out)
        if match:
            self.report.load_1m = float(match.group(1))
            self.report.load_5m = float(match.group(2))
            self.report.load_15m = float(match.group(3))

    def _interpret_load(self):
        cores = self.report.cores or 1
        r1 = self.report.load_1m / cores
        r5 = self.report.load_5m / cores
        r15 = self.report.load_15m / cores
        print(f"\n  Load / cores ratio:  1m={r1:.2f}  5m={r5:.2f}  15m={r15:.2f}")

        c = self.cfg
        if r1 >= c["cpu_load_ratio_overloaded"]:
            self._finding("cpu", "critical", f"System severely overloaded — load/cores = {r1:.2f}")
        elif r1 >= c["cpu_load_ratio_saturated"]:
            self._finding("cpu", "warning", f"System at/above saturation — load/cores = {r1:.2f}")
        elif r1 >= c["cpu_load_ratio_healthy"]:
            self._finding("cpu", "info", f"System approaching saturation — load/cores = {r1:.2f}")
        else:
            self._finding("cpu", "info", f"System load healthy — load/cores = {r1:.2f}")

        spike = c["cpu_load_spike_multiplier"]
        sustained = c["cpu_load_sustained_mult"]
        stable_tol = c["cpu_load_stable_tolerance"]
        sustained_tol = c["cpu_load_sustained_tol"]

        if r1 > r5 * spike and r5 > r15 * spike:
            self._finding("cpu", "warning", "Load spiking — issue started very recently")
        elif r1 > r15 * sustained and abs(r1 - r5) / max(r5, 0.01) < sustained_tol:
            self._finding("cpu", "warning", "Sustained elevated load — issue started within last ~10 min")
        elif abs(r1 - r15) / max(r15, 0.01) < stable_tol:
            self._finding("cpu", "info", "Load is stable — this is the system's normal state")
        elif r1 < r5 < r15:
            self._finding("cpu", "info", "Load is decreasing — system may be recovering")

    def _get_memory_overview(self):
        if self.runner.is_darwin:
            out = self.runner.run("vm_stat")
            pages = {}
            for line in out.splitlines():
                m = re.match(r'^(.+?):\s+([\d.]+)', line)
                if m:
                    pages[m.group(1).strip()] = int(m.group(2).rstrip('.'))
            page_size = 16384
            ps_out = self.runner.run("pagesize")
            if ps_out.strip().isdigit():
                page_size = int(ps_out.strip())
            total_out = self.runner.run("sysctl -n hw.memsize")
            total_bytes = int(total_out.strip()) if total_out.strip().isdigit() else 0
            active = pages.get("Pages active", 0)
            wired = pages.get("Pages wired down", 0)
            compressed = pages.get("Pages occupied by compressor", 0)
            used_bytes = (active + wired + compressed) * page_size
            total_gb = total_bytes / (1024**3)
            used_gb = used_bytes / (1024**3)
            pct = (used_gb / total_gb * 100) if total_gb > 0 else 0
            self.report.mem_total = f"{total_gb:.1f}G"
            self.report.mem_used = f"{used_gb:.1f}G"
            self.report.mem_pct = pct
            print(f"  Memory: {used_gb:.1f}G / {total_gb:.1f}G ({pct:.0f}% used)")
        else:
            out = self.runner.run("free -h")
            print(f"  {out}")
            for line in out.splitlines():
                if line.startswith("Mem:"):
                    parts = line.split()
                    self.report.mem_total = parts[1] if len(parts) > 1 else ""
                    self.report.mem_used = parts[2] if len(parts) > 2 else ""

    def _get_top_processes(self):
        procs = []
        n = self.cfg["out_top_process_count"]
        if self.runner.is_darwin:
            out = self.runner.run(f"ps -eo pid,pcpu,pmem,state,comm -r | head -{n}")
        else:
            out = self.runner.run(f"ps -eo pid,pcpu,pmem,stat,comm --sort=-pcpu | head -{n}")
        for line in out.splitlines()[1:]:
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            try:
                pid = int(parts[0])
                cpu_val = float(parts[1])
                mem_val = float(parts[2])
                state = parts[3]
                name = parts[4].strip()
                procs.append({"pid": pid, "cpu": cpu_val, "mem": mem_val, "state": state, "name": name})
            except (ValueError, IndexError):
                continue
        return procs

    def _get_d_state_processes(self):
        if self.runner.is_darwin:
            out = self.runner.run("ps -eo pid,state,comm | grep -E '^[[:space:]]*[0-9]+[[:space:]]+U'")
        else:
            out = self.runner.run("ps -eo pid,stat,comm | awk '$2 ~ /D/ {print}'")
        pids = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                try:
                    pids.append(int(parts[0]))
                except ValueError:
                    pass
        return pids

    # ── §3: Process Deep-Dive ─────────────────────────────────────────

    def _process_deep_dive(self, pid):
        if self.over_budget():
            return
        print(f"\n── §3 Process Deep-Dive — PID {pid} ──\n")

        if self.runner.is_darwin:
            out = self.runner.run(f"ps -p {pid} -o pid,ppid,user,%cpu,%mem,state,start,time,comm")
        else:
            out = self.runner.run(f"ps -p {pid} -o pid,ppid,user,%cpu,%mem,stat,start,time,comm,args")
        print(f"  {out}")

        info = self._parse_process_info(pid)
        self.report.pid = pid
        self.report.process_name = info.get("name", "unknown")
        self.report.process_user = info.get("user", "unknown")
        self.report.process_cpu = info.get("cpu", 0.0)
        self.report.process_mem = info.get("mem", 0.0)
        self.report.process_state = info.get("state", "?")

        c = self.cfg
        branches_triggered = []

        if info.get("cpu", 0) > c["cpu_process_high_pct"]:
            branches_triggered.append("cpu")
        if info.get("mem", 0) > c["mem_process_high_pct"]:
            branches_triggered.append("memory")
        if info.get("state", "").startswith("D") or info.get("state", "").startswith("U"):
            branches_triggered.append("io")

        fd_count = self._get_fd_count(pid)
        fd_limit = self._get_fd_limit(pid)
        self.report.open_files = fd_count
        self.report.file_limit = fd_limit
        if fd_limit > 0 and fd_count / fd_limit > c["fd_usage_ratio_warning"]:
            branches_triggered.append("fd")

        if self.symptom:
            keyword_map = {
                "cpu": "cpu", "memory": "memory", "mem": "memory",
                "io": "io", "disk": "io", "iowait": "io",
                "fd": "fd", "file": "fd", "descriptor": "fd",
                "network": "network", "net": "network", "connection": "network",
                "slow": "network",
            }
            symptom_lower = self.symptom.lower()
            for keyword, branch in keyword_map.items():
                if keyword in symptom_lower and branch not in branches_triggered:
                    branches_triggered.append(branch)
                    self._finding("info", "info", f"Branch '{branch}' added from symptom hint: '{self.symptom}'")

        if not branches_triggered:
            branches_triggered.append("network")

        print(f"\n  Investigation branches: {', '.join(branches_triggered)}")

        dispatch = {
            "cpu": cpu.investigate,
            "memory": memory.investigate,
            "io": disk_io.investigate,
            "fd": fd.investigate,
            "network": network.investigate,
        }
        for branch in branches_triggered:
            if self.over_budget():
                break
            dispatch[branch](self, pid)

    def _parse_process_info(self, pid):
        if self.runner.is_darwin:
            out = self.runner.run(f"ps -p {pid} -o user=,%cpu=,%mem=,state=,comm=")
        else:
            out = self.runner.run(f"ps -p {pid} -o user=,%cpu=,%mem=,stat=,comm=")
        parts = out.split(None, 4)
        if len(parts) >= 5:
            return {
                "user": parts[0],
                "cpu": float(parts[1]),
                "mem": float(parts[2]),
                "state": parts[3],
                "name": parts[4].strip(),
            }
        return {}

    def _get_fd_count(self, pid):
        out = self.runner.run(f"lsof -p {pid} 2>/dev/null | wc -l")
        try:
            return int(out.strip())
        except (ValueError, AttributeError):
            return 0

    def _get_fd_limit(self, pid):
        if self.runner.is_darwin:
            out = self.runner.run("launchctl limit maxfiles")
            parts = out.split()
            try:
                return int(parts[1]) if len(parts) > 1 else 256
            except (ValueError, IndexError):
                return 256
        else:
            out = self.runner.run(f"cat /proc/{pid}/limits 2>/dev/null | grep 'open files'")
            match = re.search(r'(\d+)\s+(\d+)', out)
            if match:
                return int(match.group(1))
        return 0

    # ── §10: Report ───────────────────────────────────────────────────

    def _print_report(self):
        r = self.report
        cores = r.cores or 1
        load_ratio = r.load_1m / cores

        print(f"\n{'='*60}")
        print(f"  TROUBLESHOOTING SUMMARY")
        print(f"{'='*60}")
        print(f"  Host:          {r.host}")
        print(f"  Timestamp:     {r.timestamp}")
        print(f"  Trigger:       {r.trigger}")
        print(f"  Duration:      {self.elapsed():.1f}s")
        print(f"")
        print(f"  System Snapshot:")
        print(f"    CPU cores:   {r.cores}")
        print(f"    Load avg:    {r.load_1m:.2f} / {r.load_5m:.2f} / {r.load_15m:.2f}  (ratio: {load_ratio:.2f})")
        print(f"    Memory:      {r.mem_used} / {r.mem_total} ({r.mem_pct:.0f}% used)")
        print(f"")
        if r.pid:
            print(f"  Offending Process:")
            print(f"    PID:         {r.pid}")
            print(f"    Name:        {r.process_name}")
            print(f"    User:        {r.process_user}")
            print(f"    %CPU:        {r.process_cpu:.1f}% (on {r.cores} cores)")
            print(f"    %MEM:        {r.process_mem:.1f}%")
            print(f"    State:       {r.process_state}")
            print(f"    Open files:  {r.open_files} / {r.file_limit}")
            print(f"")

        if r.findings:
            print(f"  Findings:")
            for f in r.findings:
                icon = {"info": " ", "warning": "!", "critical": "!!"}.get(f.severity, " ")
                print(f"    [{icon}] [{f.category}] {f.message}")
            print()

        if r.recommendations:
            print(f"  Recommendations:")
            for i, rec in enumerate(r.recommendations, 1):
                print(f"    {i}. {rec}")
            print()

        print(f"{'='*60}\n")
