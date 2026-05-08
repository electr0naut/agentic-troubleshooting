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
import os
import subprocess
import shlex
import time
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime


CMD_TIMEOUT = 10
INVESTIGATION_TIMEOUT = 300  # 5 minutes max per host

# Thresholds
CPU_HIGH_PCT = 50.0
MEM_HIGH_PCT = 50.0
FD_WARNING_RATIO = 0.5
FD_CRITICAL_RATIO = 0.8
LOAD_HEALTHY = 0.7
LOAD_SATURATED = 1.0
LOAD_OVERLOADED = 2.0
CONN_WARNING = 50
CONN_CRITICAL = 200
CLOSE_WAIT_WARNING = 5
DISK_USAGE_WARNING = 90


@dataclass
class Finding:
    category: str  # cpu, memory, io, fd, network
    severity: str  # info, warning, critical
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

    def __init__(self, host=None, ssh_user=None):
        self.host = host
        self.ssh_user = ssh_user
        self.is_local = host in (None, "localhost", "127.0.0.1")
        self.is_darwin = False
        self.log = []

    def run(self, cmd, timeout=CMD_TIMEOUT):
        if self.is_local:
            full_cmd = cmd
        else:
            remote = f"{self.ssh_user}@{self.host}" if self.ssh_user else self.host
            full_cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new {remote} {shlex.quote(cmd)}"

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
    def __init__(self, runner: CommandRunner, pid=None, symptom=None):
        self.runner = runner
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
        if self.elapsed() > INVESTIGATION_TIMEOUT:
            self._finding("info", "info", f"Investigation time limit reached ({INVESTIGATION_TIMEOUT}s)")
            return True
        return False

    def _finding(self, category, severity, message):
        self.report.findings.append(Finding(category, severity, message))
        label = {"info": ".", "warning": "!", "critical": "!!"}[severity]
        print(f"  [{label}] {message}")

    def _recommend(self, msg):
        self.report.recommendations.append(msg)

    def _pn(self, pid=None):
        """PID + short name for findings: 'PID 1234 (python3)'"""
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

    # ── System context (used by both §1→PID and §2 paths) ───────────

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

        candidate = top_procs[0]
        if candidate["cpu"] > CPU_HIGH_PCT:
            self._finding("cpu", "warning",
                          f"Top CPU consumer: PID {candidate['pid']} ({candidate['name']}) at {candidate['cpu']:.1f}%")
            return candidate["pid"]
        elif d_procs:
            return d_procs[0]
        elif top_procs:
            self._finding("info", "info",
                          f"No process above {CPU_HIGH_PCT}% CPU — examining top consumer PID {candidate['pid']}")
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

        if r1 >= LOAD_OVERLOADED:
            self._finding("cpu", "critical", f"System severely overloaded — load/cores = {r1:.2f}")
        elif r1 >= LOAD_SATURATED:
            self._finding("cpu", "warning", f"System at/above saturation — load/cores = {r1:.2f}")
        elif r1 >= LOAD_HEALTHY:
            self._finding("cpu", "info", f"System approaching saturation — load/cores = {r1:.2f}")
        else:
            self._finding("cpu", "info", f"System load healthy — load/cores = {r1:.2f}")

        if r1 > r5 * 1.5 and r5 > r15 * 1.5:
            self._finding("cpu", "warning", "Load spiking — issue started very recently")
        elif r1 > r15 * 1.3 and abs(r1 - r5) / max(r5, 0.01) < 0.3:
            self._finding("cpu", "warning", "Sustained elevated load — issue started within last ~10 min")
        elif abs(r1 - r15) / max(r15, 0.01) < 0.2:
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
        if self.runner.is_darwin:
            out = self.runner.run("ps -eo pid,pcpu,pmem,state,comm -r | head -20")
        else:
            out = self.runner.run("ps -eo pid,pcpu,pmem,stat,comm --sort=-pcpu | head -20")
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
        # macOS user-space processes almost never enter U-state (equivalent of Linux D-state).
        # I/O investigation relies on symptom hints and heuristics instead.
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

        # 3.2 Decision tree — check all branches based on metrics
        branches_triggered = []

        if info.get("cpu", 0) > CPU_HIGH_PCT:
            branches_triggered.append("cpu")
        if info.get("mem", 0) > MEM_HIGH_PCT:
            branches_triggered.append("memory")
        if info.get("state", "").startswith("D") or info.get("state", "").startswith("U"):
            branches_triggered.append("io")

        fd_count = self._get_fd_count(pid)
        fd_limit = self._get_fd_limit(pid)
        self.report.open_files = fd_count
        self.report.file_limit = fd_limit
        if fd_limit > 0 and fd_count / fd_limit > FD_WARNING_RATIO:
            branches_triggered.append("fd")

        # Symptom-based branch forcing — operator hint overrides metric thresholds
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
            # macOS has no /proc/PID/limits — use launchctl system default as approximation
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

        cores = self.report.cores or 1
        cpu_pct = self.report.process_cpu
        per_core = cpu_pct / cores
        print(f"  Process %CPU: {cpu_pct:.1f}% on {cores} cores ({per_core:.1f}% of total capacity)")

        pn = self._pn(pid)
        if cpu_pct >= 95:
            self._finding("cpu", "critical",
                          f"{pn} consuming {cpu_pct:.1f}% CPU — saturating ~{cpu_pct/100:.0f} core(s)")
        elif cpu_pct >= CPU_HIGH_PCT:
            self._finding("cpu", "warning", f"{pn} elevated CPU at {cpu_pct:.1f}%")

        # 4.2 Duration estimate
        r1 = self.report.load_1m / cores if cores else 0
        r15 = self.report.load_15m / cores if cores else 0
        if r1 > r15 * 1.5:
            self._finding("cpu", "info", "Load spike is recent (1m >> 15m) — issue started within last few minutes")
        elif abs(r1 - r15) / max(r15, 0.01) < 0.2:
            self._finding("cpu", "info", "Load is stable — CPU pressure may be chronic")

        # 4.3 System logs
        print("\n  Checking system logs...")
        if self.runner.is_darwin:
            out = self.runner.run(
                "log show --predicate 'messageType == error' --last 10m --style compact 2>/dev/null | tail -20",
                timeout=15,
            )
        else:
            out = self.runner.run(
                "journalctl --since '10 minutes ago' --priority=warning --no-pager 2>/dev/null | tail -20"
            )
        if out.strip():
            relevant = [l for l in out.splitlines() if l.strip()]
            if relevant:
                self._finding("cpu", "info", f"Found {len(relevant)} recent log entries (last 10m)")
                for line in relevant[:5]:
                    print(f"    {line[:120]}")
        else:
            print("  No recent warning/error log entries.")

        # 4.4 OOM / jetsam check
        if self.runner.is_darwin:
            out = self.runner.run(
                "log show --predicate 'eventMessage contains \"jettisoned\"' --last 10m --style compact 2>/dev/null | tail -5",
                timeout=15,
            )
            if out.strip():
                self._finding("cpu", "warning", "macOS memory jetsam events detected in last 10 minutes")
                for line in out.splitlines()[:3]:
                    print(f"    {line[:120]}")
        else:
            out = self.runner.run("dmesg -T 2>/dev/null | grep -i 'oom\\|killed process' | tail -10")
            if out.strip():
                self._finding("cpu", "warning", "OOM killer activity detected")
                for line in out.splitlines()[:3]:
                    print(f"    {line[:120]}")

        # 4.5 Thread-level breakdown
        print("\n  Thread breakdown:")
        if self.runner.is_darwin:
            out = self.runner.run(f"ps -M -p {pid} -o pid,pcpu,comm | head -20")
        else:
            out = self.runner.run(f"ps -p {pid} -L -o tid,%cpu,comm | sort -k2 -rn | head -20")
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

        # 5.1 Process memory profile
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
        if mem_pct > MEM_HIGH_PCT:
            self._finding("memory", "critical", f"{pn} RSS: {rss_mb:.0f} MB ({mem_pct:.1f}% of system)")
        elif rss_mb > 100:
            self._finding("memory", "warning", f"{pn} RSS: {rss_mb:.0f} MB ({mem_pct:.1f}% of system)")
        else:
            self._finding("memory", "info", f"{pn} RSS: {rss_mb:.0f} MB ({mem_pct:.1f}% of system)")

        if vsz_mb > rss_mb * 10 and vsz_mb > 1000:
            self._finding("memory", "info",
                          f"{pn} VSZ ({vsz_mb:.0f} MB) is {vsz_mb/max(rss_mb,1):.0f}x RSS — large virtual reservation")

        # 5.1b macOS: vmmap summary
        if self.runner.is_darwin:
            print("\n  Memory map summary:")
            out = self.runner.run(f"vmmap --summary {pid} 2>/dev/null | tail -8", timeout=15)
            if out.strip():
                print(f"  {out.replace(chr(10), chr(10) + '  ')}")
            else:
                print("  (vmmap not available or insufficient permissions)")

        # 5.2 Swap / compression check — system-wide context, attributed only
        # when this process is a significant contributor
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
                    # Only attribute to this process if it's a meaningful memory consumer
                    if used_mb > 0 and mem_pct > 5:
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
                    if compressed_mb > 2048 and mem_pct > 5:
                        self._finding("memory", "warning",
                                      f"Heavy memory compression ({compressed_mb:.0f} MB) and {pn} "
                                      f"is a significant consumer ({mem_pct:.1f}%) — may be contributing")
                    elif compressed_mb > 2048:
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
                    if proc_swap_mb > 100:
                        self._finding("memory", "warning",
                                      f"{pn} has {proc_swap_mb:.0f} MB swapped out")
                    elif proc_swap_mb > 0:
                        self._finding("memory", "info",
                                      f"{pn} has {proc_swap_mb:.0f} MB swapped out")
            out = self.runner.run("cat /proc/meminfo 2>/dev/null | grep -E 'SwapTotal|SwapFree'")
            if out:
                print(f"  {out}")

        # 5.3 Memory growth trend — 3 snapshots, 3s apart
        print("\n  RSS growth check (3 samples, 3s apart):")
        samples = []
        for i in range(3):
            rss = self.runner.run(f"ps -p {pid} -o rss=")
            try:
                samples.append(int(rss.strip()))
            except (ValueError, AttributeError):
                break
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"    {ts}  RSS = {samples[-1]/1024:.1f} MB")
            if i < 2:
                time.sleep(3)

        if len(samples) >= 2:
            growth = samples[-1] - samples[0]
            growth_pct = (growth / max(samples[0], 1)) * 100
            if growth_pct > 5:
                self._finding("memory", "warning",
                              f"{pn} RSS grew {growth/1024:.1f} MB ({growth_pct:.1f}%) over "
                              f"{(len(samples)-1)*3}s — possible leak")
            elif growth_pct > 0:
                self._finding("memory", "info", f"{pn} RSS grew slightly: +{growth/1024:.1f} MB ({growth_pct:.1f}%)")
            else:
                self._finding("memory", "info", f"{pn} RSS stable during observation window")

        # 5.4 System memory pressure (macOS)
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

        pn = self._pn(pid)
        state = self.report.process_state
        if state.startswith("D") or state.startswith("U"):
            self._finding("io", "warning", f"{pn} in uninterruptible sleep ({state}) — likely waiting on I/O")
        else:
            self._finding("io", "info", f"{pn} state is '{state}' — investigating I/O indicators")

        # 6.1 System-level I/O stats
        print("  Disk I/O stats:")
        if self.runner.is_darwin:
            out = self.runner.run("iostat -d -c 3 -w 1 2>/dev/null")
            if out:
                print(f"  {out.replace(chr(10), chr(10) + '  ')}")
        else:
            out = self.runner.run("iostat -x 1 3 2>/dev/null | tail -20")
            if out:
                print(f"  {out.replace(chr(10), chr(10) + '  ')}")
            proc_io = self.runner.run(f"cat /proc/{pid}/io 2>/dev/null")
            if proc_io:
                print(f"\n  Process I/O counters:\n  {proc_io.replace(chr(10), chr(10) + '  ')}")

        # 6.2 Identify open disk files
        print("\n  Open disk files:")
        out = self.runner.run(f"lsof -p {pid} 2>/dev/null | grep REG | head -30")
        reg_count = 0
        file_dirs = set()
        if out.strip():
            lines = [l for l in out.splitlines() if l.strip()]
            reg_count = len(lines)
            print(f"  {out.replace(chr(10), chr(10) + '  ')}")
            for line in lines:
                parts = line.split()
                if len(parts) >= 9:
                    path = parts[8]
                    import os
                    file_dirs.add(os.path.dirname(path))
        else:
            print("  (no regular files open)")

        total_fds = self.report.open_files
        if total_fds > 0 and reg_count > 0:
            reg_ratio = reg_count / total_fds
            self._finding("io", "info",
                          f"{pn} has {reg_count} regular file FDs out of {total_fds} total ({reg_ratio:.0%})")
            if reg_ratio > 0.5 and reg_count > 10:
                self._finding("io", "warning",
                              f"{pn} has high proportion of disk file FDs — I/O heavy")

        # 6.3 Map to storage devices / check disk space
        if file_dirs:
            print("\n  Filesystem usage for open file locations:")
            for d in sorted(file_dirs)[:5]:
                out = self.runner.run(f"df -h {d} 2>/dev/null | tail -1")
                if out:
                    print(f"    {out}")
                    match = re.search(r'(\d+)%', out)
                    if match and int(match.group(1)) >= DISK_USAGE_WARNING:
                        self._finding("io", "critical",
                                      f"Filesystem containing {d} is {match.group(1)}% full")

        # 6.4 I/O-bound heuristic — low CPU% but high cumulative time
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
                if cpu_pct < 10 and total_secs > 60:
                    self._finding("io", "warning",
                                  f"{pn} low current CPU ({cpu_pct:.1f}%) but {total_secs:.0f}s cumulative — "
                                  f"spends significant time waiting (likely I/O)")
            except (ValueError, IndexError):
                pass

        # 6.5 Kernel I/O errors
        print("\n  Checking for I/O errors in system logs...")
        if self.runner.is_darwin:
            out = self.runner.run(
                "log show --predicate 'sender == \"kernel\" AND messageType == error' --last 10m "
                "--style compact 2>/dev/null | grep -iE 'disk|io|storage|nand' | tail -5",
                timeout=15,
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
            elif ratio >= FD_CRITICAL_RATIO:
                self._finding("fd", "critical",
                              f"{pn} at {ratio:.0%} of FD limit ({fd_count}/{fd_limit}) — approaching exhaustion")
            elif ratio >= FD_WARNING_RATIO:
                self._finding("fd", "warning",
                              f"{pn} at {ratio:.0%} of FD limit ({fd_count}/{fd_limit})")
            else:
                self._finding("fd", "info", f"{pn} FD usage normal ({ratio:.0%})")

        # 7.1 Breakdown by type
        print("\n  FD type breakdown:")
        out = self.runner.run(f"lsof -p {pid} 2>/dev/null | awk 'NR>1 {{print $5}}' | sort | uniq -c | sort -rn")
        if out:
            print(f"  {out.replace(chr(10), chr(10) + '  ')}")

        # 7.2 Top file paths
        print("\n  Top file paths:")
        out = self.runner.run(f"lsof -p {pid} 2>/dev/null | awk 'NR>1 {{print $9}}' | sort | uniq -c | sort -rn | head -10")
        if out:
            print(f"  {out.replace(chr(10), chr(10) + '  ')}")

        # 7.3 Leak pattern classification
        print("\n  Leak pattern analysis:")

        # CLOSE_WAIT sockets
        close_wait_out = self.runner.run(
            f"lsof -p {pid} 2>/dev/null | grep -c CLOSE_WAIT"
        )
        try:
            close_wait = int(close_wait_out.strip())
        except (ValueError, AttributeError):
            close_wait = 0
        if close_wait > CLOSE_WAIT_WARNING:
            self._finding("fd", "warning",
                          f"{close_wait} sockets in CLOSE_WAIT — application not closing connections properly")
        elif close_wait > 0:
            print(f"    CLOSE_WAIT sockets: {close_wait}")

        # Duplicate directory entries (temp file leak)
        dir_out = self.runner.run(
            f"lsof -p {pid} 2>/dev/null | awk 'NR>1 && $5==\"REG\" {{n=split($9,a,\"/\"); "
            f"dir=\"\"; for(i=1;i<n;i++) dir=dir\"/\"a[i]; print dir}}' | sort | uniq -c | sort -rn | head -3"
        )
        if dir_out.strip():
            for line in dir_out.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    count = int(parts[0])
                    dirname = parts[1]
                    if count > 20:
                        self._finding("fd", "warning",
                                      f"{count} file FDs in {dirname} — possible temp file leak")

        # Pipe/FIFO count
        pipe_out = self.runner.run(f"lsof -p {pid} 2>/dev/null | grep -cE 'PIPE|FIFO'")
        try:
            pipe_count = int(pipe_out.strip())
        except (ValueError, AttributeError):
            pipe_count = 0
        if pipe_count > 20:
            self._finding("fd", "warning",
                          f"{pipe_count} pipe/FIFO FDs — possible subprocess management issue")
        elif pipe_count > 0:
            print(f"    Pipes/FIFOs: {pipe_count}")

        # 7.4 FD growth trend — 3 snapshots, 5s apart
        print("\n  FD growth check (3 samples, 5s apart):")
        fd_samples = []
        for i in range(3):
            count_out = self.runner.run(f"lsof -p {pid} 2>/dev/null | wc -l")
            try:
                fd_samples.append(int(count_out.strip()))
            except (ValueError, AttributeError):
                break
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"    {ts}  FDs = {fd_samples[-1]}")
            if i < 2:
                time.sleep(5)

        if len(fd_samples) >= 2:
            growth = fd_samples[-1] - fd_samples[0]
            if growth > 5:
                self._finding("fd", "warning",
                              f"FD count growing: +{growth} in {(len(fd_samples)-1)*5}s — active leak")
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

        # 8.1 Map connections via lsof
        out = self.runner.run(f"lsof -p {pid} -i -n -P 2>/dev/null")
        pn = self._pn(pid)
        if not out.strip():
            print("  No network connections found.")
            self._finding("network", "info", f"{pn} has no active network connections")
            return

        lines = [l for l in out.splitlines() if l.strip()]
        header = lines[0] if lines else ""
        conn_lines = lines[1:] if len(lines) > 1 else []

        print(f"  Network connections ({len(conn_lines)} total):")
        for line in conn_lines[:20]:
            print(f"    {line}")
        if len(conn_lines) > 20:
            print(f"    ... and {len(conn_lines) - 20} more")

        # 8.2 Connection state summary
        states = {}
        remote_endpoints = {}
        for line in conn_lines:
            # Parse state from lsof NAME column: "host:port->host:port (STATE)"
            state_match = re.search(r'\((\w+)\)\s*$', line)
            state = state_match.group(1) if state_match else "UNKNOWN"
            states[state] = states.get(state, 0) + 1

            # Parse remote endpoint
            arrow_match = re.search(r'->([\d.]+(?::\d+)?|[\w.-]+:\d+)', line)
            if arrow_match:
                remote = arrow_match.group(1)
                remote_ip = remote.split(":")[0]
                remote_endpoints[remote_ip] = remote_endpoints.get(remote_ip, 0) + 1

        print(f"\n  Connection states:")
        for state, count in sorted(states.items(), key=lambda x: -x[1]):
            print(f"    {state:>15}: {count}")

        total_conns = len(conn_lines)
        if total_conns >= CONN_CRITICAL:
            self._finding("network", "critical",
                          f"{pn} has {total_conns} connections — very high, possible connection leak")
        elif total_conns >= CONN_WARNING:
            self._finding("network", "warning", f"{pn} has {total_conns} connections — elevated")
        else:
            self._finding("network", "info", f"{pn} has {total_conns} connection(s)")

        # CLOSE_WAIT detection
        close_wait = states.get("CLOSE_WAIT", 0)
        if close_wait > CLOSE_WAIT_WARNING:
            self._finding("network", "warning",
                          f"{pn} has {close_wait} connections in CLOSE_WAIT — "
                          f"remote side closed but application hasn't")

        # 8.3 Queue depth check via netstat cross-reference (macOS)
        if self.runner.is_darwin:
            # Extract local ports from lsof output
            local_ports = set()
            for line in conn_lines:
                # Match patterns like "localhost:12345->" or "*:12345"
                port_match = re.search(r'(?:localhost|[\d.]+|\*):(\d+)', line)
                if port_match:
                    local_ports.add(port_match.group(1))

            if local_ports:
                print(f"\n  Checking queue depth for {len(local_ports)} local ports...")
                netstat_out = self.runner.run("netstat -an -p tcp 2>/dev/null | head -100")
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
                    for c in congested[:5]:
                        print(f"    {c}")
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

        # 8.4 Remote endpoint grouping
        if remote_endpoints:
            print(f"\n  Top remote endpoints:")
            for ip, count in sorted(remote_endpoints.items(), key=lambda x: -x[1])[:5]:
                print(f"    {ip:>20}: {count} connection(s)")
            top_ip, top_count = max(remote_endpoints.items(), key=lambda x: x[1])
            if top_count > 10:
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
    args = parser.parse_args()

    runner = CommandRunner(host=args.host, ssh_user=args.user)
    ts = Troubleshooter(runner, pid=args.pid, symptom=args.symptom)
    ts.run()


if __name__ == "__main__":
    main()
