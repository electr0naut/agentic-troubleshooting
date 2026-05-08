"""
Agentic troubleshooter — implements the decision tree from TROUBLESHOOTING_RUNBOOK.md.

Connects to a host via SSH (or runs locally) and diagnoses performance issues.
All commands are read-only, timeout-wrapped, and scoped per §0 guidelines.

CRITICAL CONSTRAINT: The agent NEVER kills, restarts, or otherwise modifies
processes or network connections. It only observes and reports. When remediation
is needed, it provides the operator with the exact command to run — elsewhere,
at their discretion.
"""
import argparse
import configparser
import os
import subprocess
import shlex
import time
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime

SETTINGS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.cfg")


def load_config(path=None):
    cfg = configparser.ConfigParser()
    cfg.read(path or SETTINGS_PATH)

    def g(section, key, fallback, cast=None):
        raw = cfg.get(section, key, fallback=str(fallback))
        return (cast or type(fallback))(raw)

    return {
        "command_timeout_secs":        g("timeouts", "command_timeout_secs", 10, int),
        "slow_command_timeout_secs":   g("timeouts", "slow_command_timeout_secs", 15, int),
        "investigation_budget_secs":   g("timeouts", "investigation_budget_secs", 300, int),
        "ssh_connect_timeout_secs":    g("timeouts", "ssh_connect_timeout_secs", 5, int),
        "log_lookback_minutes":        g("timeouts", "log_lookback_minutes", 10, int),
        "cpu_process_high_pct":        g("cpu", "process_high_pct", 50.0, float),
        "cpu_process_critical_pct":    g("cpu", "process_critical_pct", 95.0, float),
        "cpu_load_ratio_healthy":      g("cpu", "load_ratio_healthy", 0.7, float),
        "cpu_load_ratio_saturated":    g("cpu", "load_ratio_saturated", 1.0, float),
        "cpu_load_ratio_overloaded":   g("cpu", "load_ratio_overloaded", 2.0, float),
        "cpu_load_spike_multiplier":   g("cpu", "load_spike_multiplier", 1.5, float),
        "cpu_load_sustained_mult":     g("cpu", "load_sustained_multiplier", 1.3, float),
        "cpu_load_stable_tolerance":   g("cpu", "load_stable_tolerance", 0.2, float),
        "cpu_load_sustained_tol":      g("cpu", "load_sustained_tolerance", 0.3, float),
        "mem_process_high_pct":        g("memory", "process_high_pct", 50.0, float),
        "mem_rss_warning_mb":          g("memory", "process_rss_warning_mb", 100, int),
        "mem_vsz_rss_ratio_warning":   g("memory", "vsz_rss_ratio_warning", 10, int),
        "mem_vsz_absolute_warning_mb": g("memory", "vsz_absolute_warning_mb", 1000, int),
        "mem_swap_attribution_pct":    g("memory", "swap_attribution_min_pct", 5.0, float),
        "mem_compression_warning_mb":  g("memory", "compression_warning_mb", 2048, int),
        "mem_proc_swap_warning_mb":    g("memory", "process_swap_warning_mb", 100, int),
        "mem_rss_sample_interval":     g("memory", "rss_sample_interval_secs", 3, int),
        "mem_rss_sample_count":        g("memory", "rss_sample_count", 3, int),
        "mem_rss_growth_warning_pct":  g("memory", "rss_growth_warning_pct", 5.0, float),
        "io_reg_fd_ratio_warning":     g("io", "reg_fd_ratio_warning", 0.5, float),
        "io_reg_fd_count_min":         g("io", "reg_fd_count_min", 10, int),
        "io_iobound_cpu_max_pct":      g("io", "iobound_cpu_max_pct", 10.0, float),
        "io_iobound_cumtime_secs":     g("io", "iobound_cumulative_time_secs", 60, int),
        "io_disk_usage_critical_pct":  g("io", "disk_usage_critical_pct", 90, int),
        "fd_usage_ratio_warning":      g("fd", "usage_ratio_warning", 0.5, float),
        "fd_usage_ratio_critical":     g("fd", "usage_ratio_critical", 0.8, float),
        "fd_dir_leak_threshold":       g("fd", "dir_fd_leak_threshold", 20, int),
        "fd_pipe_warning":             g("fd", "pipe_fd_warning", 20, int),
        "fd_growth_active_leak":       g("fd", "growth_active_leak", 5, int),
        "fd_sample_interval":          g("fd", "fd_sample_interval_secs", 5, int),
        "fd_sample_count":             g("fd", "fd_sample_count", 3, int),
        "net_conn_count_warning":      g("network", "connection_count_warning", 50, int),
        "net_conn_count_critical":     g("network", "connection_count_critical", 200, int),
        "net_close_wait_warning":      g("network", "close_wait_warning", 5, int),
        "net_endpoint_conc_warning":   g("network", "endpoint_concentration_warning", 10, int),
        "net_display_max_conns":       g("network", "display_max_connections", 20, int),
        "out_top_process_count":       g("output", "top_process_count", 20, int),
        "out_top_thread_count":        g("output", "top_thread_count", 20, int),
        "out_max_reg_files":           g("output", "max_reg_files_shown", 30, int),
        "out_max_file_paths":          g("output", "max_file_paths_shown", 10, int),
        "out_max_dir_groups":          g("output", "max_dir_groups_shown", 3, int),
        "out_max_log_lines":           g("output", "max_log_lines", 20, int),
        "out_max_netstat_lines":       g("output", "max_netstat_lines", 100, int),
    }


@dataclass
class Finding:
    category: str
    severity: str
    message: str


@dataclass
class Report:
    host: str
    timestamp: str
    trigger: str
    cores: int = 0
    load_1m: float = 0.0
    load_5m: float = 0.0
    load_15m: float = 0.0
    mem_total: str = ""
    mem_used: str = ""
    mem_pct: float = 0.0
    pid: int = 0
    process_name: str = ""
    process_user: str = ""
    process_cpu: float = 0.0
    process_mem: float = 0.0
    process_state: str = ""
    open_files: int = 0
    file_limit: int = 0
    findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)


class CommandRunner:
    """Executes commands locally or over SSH with timeout wrapping."""

    def __init__(self, host=None, ssh_user=None, cfg=None):
        self.host = host
        self.ssh_user = ssh_user
        self.is_local = host in (None, "localhost", "127.0.0.1")
        self.is_darwin = False
        self.log = []
        self.cfg = cfg or load_config()

    def run(self, cmd, timeout=None):
        if timeout is None:
            timeout = self.cfg["command_timeout_secs"]
        if self.is_local:
            full_cmd = cmd
        else:
            remote = f"{self.ssh_user}@{self.host}" if self.ssh_user else self.host
            ssh_to = self.cfg["ssh_connect_timeout_secs"]
            full_cmd = f"ssh -o ConnectTimeout={ssh_to} -o StrictHostKeyChecking=accept-new {remote} {shlex.quote(cmd)}"

        entry = {"time": datetime.now().isoformat(), "cmd": cmd, "host": self.host or "localhost"}
        try:
            result = subprocess.run(
                full_cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout.strip()
            stderr = result.stderr.strip()
            entry["stdout"] = output
            entry["stderr"] = stderr
            entry["rc"] = result.returncode
        except subprocess.TimeoutExpired:
            output = ""
            entry["error"] = f"timeout after {timeout}s"
            print(f"  [TIMEOUT] {cmd} (>{timeout}s)", file=sys.stderr)
        self.log.append(entry)
        return output

    def detect_os(self):
        uname = self.run("uname -s")
        self.is_darwin = uname.strip().lower() == "darwin"
        return uname


class Troubleshooter:
    def __init__(self, runner: CommandRunner, pid=None, symptom=None, cfg=None):
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
                cpu = float(parts[1])
                mem = float(parts[2])
                state = parts[3]
                name = parts[4].strip()
                procs.append({"pid": pid, "cpu": cpu, "mem": mem, "state": state, "name": name})
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

        for branch in branches_triggered:
            if self.over_budget():
                break
            if branch == "cpu":
                self._cpu_investigation(pid)
            elif branch == "memory":
                self._memory_investigation(pid)
            elif branch == "io":
                self._io_investigation(pid)
            elif branch == "fd":
                self._fd_investigation(pid)
            elif branch == "network":
                self._network_investigation(pid)

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

    # ── §4: CPU Investigation ─────────────────────────────────────────

    def _cpu_investigation(self, pid):
        if self.over_budget():
            return
        print(f"\n── §4 CPU Investigation — PID {pid} ──\n")

        c = self.cfg
        cores = self.report.cores or 1
        cpu_pct = self.report.process_cpu
        per_core = cpu_pct / cores
        print(f"  Process %CPU: {cpu_pct:.1f}% on {cores} cores ({per_core:.1f}% of total capacity)")

        pn = self._pn(pid)
        if cpu_pct >= c["cpu_process_critical_pct"]:
            self._finding("cpu", "critical",
                          f"{pn} consuming {cpu_pct:.1f}% CPU — saturating ~{cpu_pct/100:.0f} core(s)")
        elif cpu_pct >= c["cpu_process_high_pct"]:
            self._finding("cpu", "warning", f"{pn} elevated CPU at {cpu_pct:.1f}%")

        r1 = self.report.load_1m / cores if cores else 0
        r15 = self.report.load_15m / cores if cores else 0
        if r1 > r15 * c["cpu_load_spike_multiplier"]:
            self._finding("cpu", "info", "Load spike is recent (1m >> 15m) — issue started within last few minutes")
        elif abs(r1 - r15) / max(r15, 0.01) < c["cpu_load_stable_tolerance"]:
            self._finding("cpu", "info", "Load is stable — CPU pressure may be chronic")

        lookback = c["log_lookback_minutes"]
        max_log = c["out_max_log_lines"]
        slow_to = c["slow_command_timeout_secs"]

        print("\n  Checking system logs...")
        if self.runner.is_darwin:
            out = self.runner.run(
                f"log show --predicate 'messageType == error' --last {lookback}m "
                f"--style compact 2>/dev/null | tail -{max_log}",
                timeout=slow_to,
            )
        else:
            out = self.runner.run(
                f"journalctl --since '{lookback} minutes ago' --priority=warning "
                f"--no-pager 2>/dev/null | tail -{max_log}"
            )
        if out.strip():
            relevant = [l for l in out.splitlines() if l.strip()]
            if relevant:
                self._finding("cpu", "info", f"Found {len(relevant)} recent log entries (last {lookback}m)")
                for line in relevant[:5]:
                    print(f"    {line[:120]}")
        else:
            print("  No recent warning/error log entries.")

        if self.runner.is_darwin:
            out = self.runner.run(
                f"log show --predicate 'eventMessage contains \"jettisoned\"' --last {lookback}m "
                f"--style compact 2>/dev/null | tail -5",
                timeout=slow_to,
            )
            if out.strip():
                self._finding("cpu", "warning", f"macOS memory jetsam events detected in last {lookback} minutes")
                for line in out.splitlines()[:3]:
                    print(f"    {line[:120]}")
        else:
            out = self.runner.run("dmesg -T 2>/dev/null | grep -i 'oom\\|killed process' | tail -10")
            if out.strip():
                self._finding("cpu", "warning", "OOM killer activity detected")
                for line in out.splitlines()[:3]:
                    print(f"    {line[:120]}")

        n_threads = c["out_top_thread_count"]
        print("\n  Thread breakdown:")
        if self.runner.is_darwin:
            out = self.runner.run(f"ps -M -p {pid} -o pid,pcpu,comm | head -{n_threads}")
        else:
            out = self.runner.run(f"ps -p {pid} -L -o tid,%cpu,comm | sort -k2 -rn | head -{n_threads}")
        if out.strip():
            print(f"  {out.replace(chr(10), chr(10) + '  ')}")

        name = self.report.process_name
        self._recommend(
            f"PID {pid} ({name}) is consuming {cpu_pct:.1f}% CPU. "
            f"To profile, operator may run:  sample {pid} 5 -file /tmp/{pid}.sample  (macOS) "
            f"or  perf record -p {pid} -g -- sleep 5  (Linux). "
            f"Do NOT kill or restart the process from this agent."
        )

    # ── §5: Memory Investigation ──────────────────────────────────────

    def _memory_investigation(self, pid):
        if self.over_budget():
            return
        print(f"\n── §5 Memory Investigation — PID {pid} ──\n")

        c = self.cfg
        out = self.runner.run(f"ps -p {pid} -o pid,rss,vsz,%mem,comm")
        print(f"  {out}")

        rss_out = self.runner.run(f"ps -p {pid} -o rss=")
        vsz_out = self.runner.run(f"ps -p {pid} -o vsz=")
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

        pn = self._pn(pid)
        mem_pct = self.report.process_mem
        if mem_pct > c["mem_process_high_pct"]:
            self._finding("memory", "critical", f"{pn} RSS: {rss_mb:.0f} MB ({mem_pct:.1f}% of system)")
        elif rss_mb > c["mem_rss_warning_mb"]:
            self._finding("memory", "warning", f"{pn} RSS: {rss_mb:.0f} MB ({mem_pct:.1f}% of system)")
        else:
            self._finding("memory", "info", f"{pn} RSS: {rss_mb:.0f} MB ({mem_pct:.1f}% of system)")

        if vsz_mb > rss_mb * c["mem_vsz_rss_ratio_warning"] and vsz_mb > c["mem_vsz_absolute_warning_mb"]:
            self._finding("memory", "info",
                          f"{pn} VSZ ({vsz_mb:.0f} MB) is {vsz_mb/max(rss_mb,1):.0f}x RSS — large virtual reservation")

        if self.runner.is_darwin:
            print("\n  Memory map summary:")
            out = self.runner.run(f"vmmap --summary {pid} 2>/dev/null | tail -8",
                                  timeout=c["slow_command_timeout_secs"])
            if out.strip():
                print(f"  {out.replace(chr(10), chr(10) + '  ')}")
            else:
                print("  (vmmap not available or insufficient permissions)")

        attr_pct = c["mem_swap_attribution_pct"]
        comp_warn = c["mem_compression_warning_mb"]

        print("\n  Swap & compression check (system-wide context):")
        if self.runner.is_darwin:
            out = self.runner.run("sysctl vm.swapusage")
            if out:
                print(f"  {out}")
                match = re.search(r'used\s*=\s*([\d.]+)([MG])', out)
                if match:
                    used_val = float(match.group(1))
                    unit = match.group(2)
                    used_mb = used_val * 1024 if unit == "G" else used_val
                    if used_mb > 0 and mem_pct > attr_pct:
                        self._finding("memory", "warning",
                                      f"System swap in use ({used_val:.1f}{unit}) and {pn} "
                                      f"is consuming {mem_pct:.1f}% of RAM — may be contributing to swap pressure")
                    elif used_mb > 0:
                        self._finding("memory", "info",
                                      f"System swap in use ({used_val:.1f}{unit}) but {pn} "
                                      f"is only {mem_pct:.1f}% of RAM — swap is from other processes")
                    else:
                        self._finding("memory", "info", "No swap in use")

            out = self.runner.run("vm_stat | grep compressor")
            if out:
                match = re.search(r'(\d+)', out)
                if match:
                    page_size_out = self.runner.run("pagesize")
                    page_size = int(page_size_out.strip()) if page_size_out.strip().isdigit() else 16384
                    compressed_mb = int(match.group(1)) * page_size / (1024 * 1024)
                    print(f"  Compressed memory: {compressed_mb:.0f} MB")
                    if compressed_mb > comp_warn and mem_pct > attr_pct:
                        self._finding("memory", "warning",
                                      f"Heavy memory compression ({compressed_mb:.0f} MB) and {pn} "
                                      f"is a significant consumer ({mem_pct:.1f}%) — may be contributing")
                    elif compressed_mb > comp_warn:
                        self._finding("memory", "info",
                                      f"System memory compression active ({compressed_mb:.0f} MB) — "
                                      f"not attributed to {pn} ({mem_pct:.1f}% of RAM)")
        else:
            out = self.runner.run(f"grep -i swap /proc/{pid}/status 2>/dev/null")
            if out:
                print(f"  {out}")
                swap_match = re.search(r'VmSwap:\s+(\d+)\s+kB', out)
                if swap_match:
                    proc_swap_mb = int(swap_match.group(1)) / 1024
                    if proc_swap_mb > c["mem_proc_swap_warning_mb"]:
                        self._finding("memory", "warning",
                                      f"{pn} has {proc_swap_mb:.0f} MB swapped out")
                    elif proc_swap_mb > 0:
                        self._finding("memory", "info",
                                      f"{pn} has {proc_swap_mb:.0f} MB swapped out")
            out = self.runner.run("cat /proc/meminfo 2>/dev/null | grep -E 'SwapTotal|SwapFree'")
            if out:
                print(f"  {out}")

        sample_count = c["mem_rss_sample_count"]
        sample_interval = c["mem_rss_sample_interval"]
        print(f"\n  RSS growth check ({sample_count} samples, {sample_interval}s apart):")
        samples = []
        for i in range(sample_count):
            rss = self.runner.run(f"ps -p {pid} -o rss=")
            try:
                samples.append(int(rss.strip()))
            except (ValueError, AttributeError):
                break
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"    {ts}  RSS = {samples[-1]/1024:.1f} MB")
            if i < sample_count - 1:
                time.sleep(sample_interval)

        if len(samples) >= 2:
            growth = samples[-1] - samples[0]
            growth_pct = (growth / max(samples[0], 1)) * 100
            if growth_pct > c["mem_rss_growth_warning_pct"]:
                self._finding("memory", "warning",
                              f"{pn} RSS grew {growth/1024:.1f} MB ({growth_pct:.1f}%) over "
                              f"{(len(samples)-1)*sample_interval}s — possible leak")
            elif growth_pct > 0:
                self._finding("memory", "info", f"{pn} RSS grew slightly: +{growth/1024:.1f} MB ({growth_pct:.1f}%)")
            else:
                self._finding("memory", "info", f"{pn} RSS stable during observation window")

        if self.runner.is_darwin:
            out = self.runner.run("memory_pressure 2>/dev/null | head -5")
            if out:
                print(f"\n  Memory pressure:\n  {out.replace(chr(10), chr(10) + '  ')}")
                if "critical" in out.lower():
                    self._finding("memory", "critical", "System under CRITICAL memory pressure")
                elif "warn" in out.lower():
                    self._finding("memory", "warning", "System under memory pressure (warning level)")

        self._recommend(
            f"PID {pid} using {rss_mb:.0f} MB RSS ({mem_pct:.1f}% of system memory). "
            f"To monitor for leak, operator may run:  "
            f"watch -n5 'ps -p {pid} -o rss=,vsz=,%mem='  "
            f"Do NOT kill or restart the process from this agent."
        )

    # ── §6: I/O Investigation ─────────────────────────────────────────

    def _io_investigation(self, pid):
        if self.over_budget():
            return
        print(f"\n── §6 I/O Investigation — PID {pid} ──\n")

        c = self.cfg
        pn = self._pn(pid)
        state = self.report.process_state
        if state.startswith("D") or state.startswith("U"):
            self._finding("io", "warning", f"{pn} in uninterruptible sleep ({state}) — likely waiting on I/O")
        else:
            self._finding("io", "info", f"{pn} state is '{state}' — investigating I/O indicators")

        print("  Disk I/O stats:")
        if self.runner.is_darwin:
            out = self.runner.run("iostat -d -c 3 -w 1 2>/dev/null")
            if out:
                print(f"  {out.replace(chr(10), chr(10) + '  ')}")
        else:
            max_log = c["out_max_log_lines"]
            out = self.runner.run(f"iostat -x 1 3 2>/dev/null | tail -{max_log}")
            if out:
                print(f"  {out.replace(chr(10), chr(10) + '  ')}")
            proc_io = self.runner.run(f"cat /proc/{pid}/io 2>/dev/null")
            if proc_io:
                print(f"\n  Process I/O counters:\n  {proc_io.replace(chr(10), chr(10) + '  ')}")

        max_reg = c["out_max_reg_files"]
        print("\n  Open disk files:")
        out = self.runner.run(f"lsof -p {pid} 2>/dev/null | grep REG | head -{max_reg}")
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

        total_fds = self.report.open_files
        if total_fds > 0 and reg_count > 0:
            reg_ratio = reg_count / total_fds
            self._finding("io", "info",
                          f"{pn} has {reg_count} regular file FDs out of {total_fds} total ({reg_ratio:.0%})")
            if reg_ratio > c["io_reg_fd_ratio_warning"] and reg_count > c["io_reg_fd_count_min"]:
                self._finding("io", "warning",
                              f"{pn} has high proportion of disk file FDs — I/O heavy")

        if file_dirs:
            print("\n  Filesystem usage for open file locations:")
            for d in sorted(file_dirs)[:5]:
                out = self.runner.run(f"df -h {d} 2>/dev/null | tail -1")
                if out:
                    print(f"    {out}")
                    match = re.search(r'(\d+)%', out)
                    if match and int(match.group(1)) >= c["io_disk_usage_critical_pct"]:
                        self._finding("io", "critical",
                                      f"Filesystem containing {d} is {match.group(1)}% full")

        cpu_pct = self.report.process_cpu
        cputime_out = self.runner.run(f"ps -p {pid} -o time=")
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
                    self._finding("io", "warning",
                                  f"{pn} low current CPU ({cpu_pct:.1f}%) but {total_secs:.0f}s cumulative — "
                                  f"spends significant time waiting (likely I/O)")
            except (ValueError, IndexError):
                pass

        lookback = c["log_lookback_minutes"]
        slow_to = c["slow_command_timeout_secs"]
        print("\n  Checking for I/O errors in system logs...")
        if self.runner.is_darwin:
            out = self.runner.run(
                f"log show --predicate 'sender == \"kernel\" AND messageType == error' --last {lookback}m "
                f"--style compact 2>/dev/null | grep -iE 'disk|io|storage|nand' | tail -5",
                timeout=slow_to,
            )
        else:
            out = self.runner.run("dmesg -T 2>/dev/null | grep -iE 'error.*sd|i/o error|bad sector' | tail -10")
        if out.strip():
            self._finding("io", "warning", "I/O related errors found in system logs")
            for line in out.splitlines()[:3]:
                print(f"    {line[:120]}")
        else:
            print("  No I/O errors found in recent logs.")

        self._recommend(
            f"PID {pid} shows I/O activity. Operator should investigate storage health. "
            f"To inspect further:  iostat -d -c 10 -w 1  (macOS) or  iostat -x 1 5  (Linux). "
            f"Check  lsof -p {pid}  for file access patterns. "
            f"Do NOT kill or restart the process from this agent."
        )

    # ── §7: File Descriptor Investigation ─────────────────────────────

    def _fd_investigation(self, pid):
        if self.over_budget():
            return
        print(f"\n── §7 File Descriptor Investigation — PID {pid} ──\n")

        c = self.cfg
        fd_count = self.report.open_files
        fd_limit = self.report.file_limit

        pn = self._pn(pid)
        print(f"  Open files:  {fd_count}")
        print(f"  Soft limit:  {fd_limit}")

        if fd_limit > 0:
            ratio = fd_count / fd_limit
            print(f"  Usage:       {ratio:.0%}")

            if ratio >= 1.0:
                self._finding("fd", "critical",
                              f"{pn} has REACHED FD limit ({fd_count}/{fd_limit}) — new opens will fail")
            elif ratio >= c["fd_usage_ratio_critical"]:
                self._finding("fd", "critical",
                              f"{pn} at {ratio:.0%} of FD limit ({fd_count}/{fd_limit}) — approaching exhaustion")
            elif ratio >= c["fd_usage_ratio_warning"]:
                self._finding("fd", "warning",
                              f"{pn} at {ratio:.0%} of FD limit ({fd_count}/{fd_limit})")
            else:
                self._finding("fd", "info", f"{pn} FD usage normal ({ratio:.0%})")

        print("\n  FD type breakdown:")
        out = self.runner.run(f"lsof -p {pid} 2>/dev/null | awk 'NR>1 {{print $5}}' | sort | uniq -c | sort -rn")
        if out:
            print(f"  {out.replace(chr(10), chr(10) + '  ')}")

        max_paths = c["out_max_file_paths"]
        print("\n  Top file paths:")
        out = self.runner.run(
            f"lsof -p {pid} 2>/dev/null | awk 'NR>1 {{print $9}}' | sort | uniq -c | sort -rn | head -{max_paths}")
        if out:
            print(f"  {out.replace(chr(10), chr(10) + '  ')}")

        print("\n  Leak pattern analysis:")

        close_wait_out = self.runner.run(f"lsof -p {pid} 2>/dev/null | grep -c CLOSE_WAIT")
        try:
            close_wait = int(close_wait_out.strip())
        except (ValueError, AttributeError):
            close_wait = 0
        if close_wait > c["net_close_wait_warning"]:
            self._finding("fd", "warning",
                          f"{close_wait} sockets in CLOSE_WAIT — application not closing connections properly")
        elif close_wait > 0:
            print(f"    CLOSE_WAIT sockets: {close_wait}")

        max_dirs = c["out_max_dir_groups"]
        dir_out = self.runner.run(
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
                        self._finding("fd", "warning",
                                      f"{count} file FDs in {dirname} — possible temp file leak")

        pipe_out = self.runner.run(f"lsof -p {pid} 2>/dev/null | grep -cE 'PIPE|FIFO'")
        try:
            pipe_count = int(pipe_out.strip())
        except (ValueError, AttributeError):
            pipe_count = 0
        if pipe_count > c["fd_pipe_warning"]:
            self._finding("fd", "warning",
                          f"{pipe_count} pipe/FIFO FDs — possible subprocess management issue")
        elif pipe_count > 0:
            print(f"    Pipes/FIFOs: {pipe_count}")

        fd_n = c["fd_sample_count"]
        fd_interval = c["fd_sample_interval"]
        print(f"\n  FD growth check ({fd_n} samples, {fd_interval}s apart):")
        fd_samples = []
        for i in range(fd_n):
            count_out = self.runner.run(f"lsof -p {pid} 2>/dev/null | wc -l")
            try:
                fd_samples.append(int(count_out.strip()))
            except (ValueError, AttributeError):
                break
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"    {ts}  FDs = {fd_samples[-1]}")
            if i < fd_n - 1:
                time.sleep(fd_interval)

        if len(fd_samples) >= 2:
            growth = fd_samples[-1] - fd_samples[0]
            if growth > c["fd_growth_active_leak"]:
                self._finding("fd", "warning",
                              f"FD count growing: +{growth} in {(len(fd_samples)-1)*fd_interval}s — active leak")
            elif growth > 0:
                self._finding("fd", "info", f"FD count slightly increasing: +{growth}")
            else:
                self._finding("fd", "info", "FD count stable during observation window")

        self._recommend(
            f"PID {pid} has {fd_count} open FDs vs limit {fd_limit}. "
            f"Operator may inspect with:  lsof -p {pid}  "
            f"To raise limit:  ulimit -n <new_limit>  (before launching the process). "
            f"Do NOT kill or restart the process from this agent."
        )

    # ── §8: Network & Dependency Investigation ────────────────────────

    def _network_investigation(self, pid):
        if self.over_budget():
            return
        print(f"\n── §8 Network & Dependency Investigation — PID {pid} ──\n")

        c = self.cfg
        out = self.runner.run(f"lsof -p {pid} -i -n -P 2>/dev/null")
        pn = self._pn(pid)
        if not out.strip():
            print("  No network connections found.")
            self._finding("network", "info", f"{pn} has no active network connections")
            return

        lines = [l for l in out.splitlines() if l.strip()]
        conn_lines = lines[1:] if len(lines) > 1 else []
        max_display = c["net_display_max_conns"]

        print(f"  Network connections ({len(conn_lines)} total):")
        for line in conn_lines[:max_display]:
            print(f"    {line}")
        if len(conn_lines) > max_display:
            print(f"    ... and {len(conn_lines) - max_display} more")

        states = {}
        remote_endpoints = {}
        for line in conn_lines:
            state_match = re.search(r'\((\w+)\)\s*$', line)
            state = state_match.group(1) if state_match else "UNKNOWN"
            states[state] = states.get(state, 0) + 1

            arrow_match = re.search(r'->([\d.]+(?::\d+)?|[\w.-]+:\d+)', line)
            if arrow_match:
                remote = arrow_match.group(1)
                remote_ip = remote.split(":")[0]
                remote_endpoints[remote_ip] = remote_endpoints.get(remote_ip, 0) + 1

        print(f"\n  Connection states:")
        for state, count in sorted(states.items(), key=lambda x: -x[1]):
            print(f"    {state:>15}: {count}")

        total_conns = len(conn_lines)
        if total_conns >= c["net_conn_count_critical"]:
            self._finding("network", "critical",
                          f"{pn} has {total_conns} connections — very high, possible connection leak")
        elif total_conns >= c["net_conn_count_warning"]:
            self._finding("network", "warning", f"{pn} has {total_conns} connections — elevated")
        else:
            self._finding("network", "info", f"{pn} has {total_conns} connection(s)")

        close_wait = states.get("CLOSE_WAIT", 0)
        if close_wait > c["net_close_wait_warning"]:
            self._finding("network", "warning",
                          f"{pn} has {close_wait} connections in CLOSE_WAIT — "
                          f"remote side closed but application hasn't")

        if self.runner.is_darwin:
            local_ports = set()
            for line in conn_lines:
                port_match = re.search(r'(?:localhost|[\d.]+|\*):(\d+)', line)
                if port_match:
                    local_ports.add(port_match.group(1))

            if local_ports:
                max_ns = c["out_max_netstat_lines"]
                print(f"\n  Checking queue depth for {len(local_ports)} local ports...")
                netstat_out = self.runner.run(f"netstat -an -p tcp 2>/dev/null | head -{max_ns}")
                congested = []
                for ns_line in netstat_out.splitlines():
                    for port in local_ports:
                        if f".{port} " in ns_line or f".{port}\t" in ns_line:
                            parts = ns_line.split()
                            if len(parts) >= 4:
                                try:
                                    recv_q = int(parts[0]) if parts[0].isdigit() else 0
                                    send_q = int(parts[1]) if parts[1].isdigit() else 0
                                    if recv_q > 0 or send_q > 0:
                                        congested.append(
                                            f"port {port}: Recv-Q={recv_q} Send-Q={send_q}")
                                except (ValueError, IndexError):
                                    pass
                if congested:
                    self._finding("network", "warning",
                                  f"{pn} has {len(congested)} congested connections (non-zero queues)")
                    for item in congested[:5]:
                        print(f"    {item}")
                else:
                    print("  No queue congestion detected.")
        else:
            out = self.runner.run(f"ss -tnp 2>/dev/null | grep {pid}")
            if out:
                queued = []
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            recv_q = int(parts[1])
                            send_q = int(parts[2])
                            if recv_q > 0 or send_q > 0:
                                queued.append(line.strip())
                        except (ValueError, IndexError):
                            pass
                if queued:
                    self._finding("network", "warning",
                                  f"{pn} has {len(queued)} connections with non-zero queue depth — possible congestion")
                    for q in queued[:5]:
                        print(f"    {q}")

        if remote_endpoints:
            print(f"\n  Top remote endpoints:")
            for ip, count in sorted(remote_endpoints.items(), key=lambda x: -x[1])[:5]:
                print(f"    {ip:>20}: {count} connection(s)")
            top_ip, top_count = max(remote_endpoints.items(), key=lambda x: x[1])
            if top_count > c["net_endpoint_conc_warning"]:
                self._finding("network", "info",
                              f"{pn} highest concentration: {top_count} connections to {top_ip}")

        self._recommend(
            f"PID {pid} has {total_conns} network connections. "
            f"Operator should inspect with:  lsof -p {pid} -i -n -P  "
            f"For queue depth:  netstat -an -p tcp  (macOS) or  ss -tnp  (Linux). "
            f"Do NOT kill or restart the process from this agent."
        )

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


def main():
    parser = argparse.ArgumentParser(description="Agentic Linux troubleshooter")
    parser.add_argument("--host", default="localhost", help="Target host (default: localhost)")
    parser.add_argument("--user", default=None, help="SSH user for remote hosts")
    parser.add_argument("--pid", type=int, default=None, help="Specific PID to investigate")
    parser.add_argument("--symptom", default=None, help="Symptom description")
    parser.add_argument("--config", default=None, help="Path to settings.cfg (default: ./settings.cfg)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    runner = CommandRunner(host=args.host, ssh_user=args.user, cfg=cfg)
    ts = Troubleshooter(runner, pid=args.pid, symptom=args.symptom)
    ts.run()


if __name__ == "__main__":
    main()
