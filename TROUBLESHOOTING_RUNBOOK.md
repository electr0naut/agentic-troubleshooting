# Agentic Troubleshooting Runbook

A logical decision tree for automated Linux server troubleshooting via SSH. Designed for an agent that connects to remote hosts, diagnoses performance issues, and reports findings.

---

## 1. Entry Point

The agent is triggered with:
- **Target host** (required): hostname or IP to SSH into
- **PID** (optional): a specific process to investigate
- **Symptom description** (optional): e.g. "server is slow", "app unresponsive"

```
START
  ├─ PID provided? ──► Go to §3 (Process Deep-Dive)
  └─ No PID ──► Go to §2 (System-Wide Triage)
```

---

## 2. System-Wide Triage

Goal: build a snapshot of overall system health and identify the most suspicious process.

### 2.1 Gather System Context

```bash
# Understand CPU topology first — all %CPU interpretation depends on this
lscpu | grep -E '^CPU\(s\)|^Thread|^Core|^Socket|^Model name'

# System uptime and load averages (1m, 5m, 15m)
uptime

# One-shot top sorted by CPU, then by memory
top -bn1 -o %CPU | head -30
top -bn1 -o %MEM | head -30

# Memory overview
free -h

# Processes in uninterruptible sleep (D state) — waiting on I/O
ps aux | awk '$8 ~ /D/ {print}'
```

### 2.2 Interpret Load Average

```
Load average vs. CPU cores:
  cores = $(nproc)

  load_1m / cores → current pressure
  load_5m / cores → short-term trend
  load_15m / cores → baseline

  ┌─────────────────────────────────────────────────────┐
  │ ratio < 0.7   → system is healthy                   │
  │ ratio 0.7–1.0 → approaching saturation              │
  │ ratio > 1.0   → overloaded (queuing)                │
  │ ratio > 2.0   → severely overloaded                 │
  └─────────────────────────────────────────────────────┘
```

#### Load Trend Analysis

```
  1m >> 5m >> 15m  → spike just started, may be transient
  1m ≈ 5m >> 15m   → sustained issue, started within last ~10 min
  1m ≈ 5m ≈ 15m    → chronic load, this is the new normal
  1m << 5m << 15m   → recovering, issue may have passed
```

### 2.3 Identify the Offending Process

From the top output, rank processes by:
1. **%CPU** (normalized: a single-threaded process can show >100% on multi-core)
2. **%MEM** (RSS as percentage of total physical memory)
3. **STATE** (D = uninterruptible sleep, R = running, S = sleeping)
4. **TIME+** (cumulative CPU time — high values on low-%CPU processes suggest intermittent bursts)

Select the top candidate PID and proceed to §3.

---

## 3. Process Deep-Dive

Given a PID (from §2 or provided at entry), investigate root cause.

### 3.1 Process Identity

```bash
# What is this process?
ps -p <pid> -o pid,ppid,user,%cpu,%mem,stat,start,time,comm,args

# How long has it been running?
ps -p <pid> -o etimes=

# What application does it belong to?
# (gateway, OMS, feedhandler, quant app, infra service, etc.)
```

### 3.2 Decision Tree — What's Wrong?

```
Examine process state and resource usage:

  ┌─ High %CPU? ────────────────► §4 (CPU Investigation)
  │
  ├─ High %MEM? ────────────────► §5 (Memory Investigation)
  │
  ├─ State = D (uninterruptible)? ► §6 (I/O Investigation)
  │
  ├─ High open file count? ─────► §7 (File Descriptor Investigation)
  │
  └─ None obvious? ─────────────► §8 (Network & Dependency Investigation)
```

> **Note:** Multiple branches can apply simultaneously. The agent should evaluate all and report combined findings.

---

## 4. CPU Investigation

### 4.1 Confirm CPU Pressure

```bash
lscpu | grep '^CPU(s):'           # total logical CPUs
ps -p <pid> -o %cpu=              # process CPU usage

# A process showing 400% CPU on a 4-core box = fully saturating all cores
# A process showing 100% on a 64-core box = using 1 core (may still be the bottleneck)
```

### 4.2 Determine Duration

```bash
uptime
# Compare load averages:
#   1m high, 15m normal  → started recently
#   all three high       → sustained issue
```

### 4.3 Correlate with System Logs

```bash
# Check logs around the time the issue likely started
# If 1m >> 15m, focus on the last few minutes
journalctl --since "10 minutes ago" --priority=warning --no-pager | tail -50

# Application-specific logs if known
# (expand per application — see §9 for app-specific paths)

# Check for OOM killer activity
dmesg -T | grep -i "oom\|killed process" | tail -20

# Check syslog for hardware errors, thermal throttling
dmesg -T | grep -iE "error|thermal|throttl|mce" | tail -20
```

### 4.4 Thread-Level Breakdown

```bash
# Which threads inside the process are consuming CPU?
ps -p <pid> -L -o tid,%cpu,comm | sort -k2 -rn | head -20

# For Java/JVM processes
# jstack <pid> | grep -A 2 "nid=<hex_tid>"

# strace snapshot (brief, non-intrusive)
timeout 5 strace -cp <pid> 2>&1
```

### 4.5 Report

Communicate to chat:
- Process name, PID, owning user
- Current %CPU normalized to core count
- Duration estimate (from load average trend)
- Relevant log entries
- Thread-level hotspot if identifiable

```
► If resolved or explained → §10 (Summary)
► If CPU is not the root cause → return to §3.2
```

---

## 5. Memory Investigation

### 5.1 Process Memory Profile

```bash
# Resident vs virtual memory
ps -p <pid> -o pid,rss,vsz,%mem,comm

# Detailed memory map
pmap -x <pid> | tail -5

# System-wide memory pressure
free -h
cat /proc/meminfo | grep -E 'MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree'
```

### 5.2 Swap Activity

```bash
# Is the system swapping?
vmstat 1 5

# Is THIS process swapped out?
grep -i swap /proc/<pid>/status
cat /proc/<pid>/smaps_rollup 2>/dev/null | grep -i swap
```

### 5.3 Memory Growth Trend

```bash
# Snapshot RSS over a short window to detect leaks
for i in 1 2 3 4 5; do
  ps -p <pid> -o rss= | awk '{print strftime("%H:%M:%S"), $1/1024 " MB"}'
  sleep 5
done
```

### 5.4 Report

Communicate to chat:
- RSS and %MEM
- Whether system is swapping
- Growth trend if observable
- OOM risk assessment

```
► If resolved or explained → §10 (Summary)
► If memory is not the root cause → return to §3.2
```

---

## 6. I/O Investigation

Triggered when process is in **D state** (uninterruptible sleep) — typically waiting on disk or network I/O.

### 6.1 Confirm I/O Wait

```bash
# Process state
ps -p <pid> -o pid,stat,wchan=

# System-wide I/O wait
iostat -x 1 3

# Per-process I/O stats
cat /proc/<pid>/io

# iowait percentage from top
top -bn1 | head -5 | grep '%Cpu'
```

### 6.2 Identify the Storage Device

```bash
# What files/devices is the process waiting on?
lsof -p <pid> | grep -E 'REG|BLK|DIR' | head -30

# Map file paths to mount points and devices
df -h $(lsof -p <pid> 2>/dev/null | awk '/REG/ {print $9}' | head -5)

# Device-level I/O stats
iostat -xp 1 3
# Look for: high await, high %util, low throughput on the identified device
```

### 6.3 Storage Device Deep-Dive

```bash
# Identify the offending device (e.g., sda, nvme0n1)
# Check queue depth and latency
cat /sys/block/<device>/queue/nr_requests
cat /sys/block/<device>/stat

# Check for disk errors
smartctl -a /dev/<device> 2>/dev/null | grep -iE 'error|reallocat|pending|uncorrect'
dmesg -T | grep -i "<device>" | tail -10
```

### 6.4 Network I/O (if not local storage)

```bash
# Is the process waiting on a network resource?
lsof -p <pid> -i | head -20

# Network connection states
ss -tnp | grep <pid>

# → If network related, proceed to §8
```

### 6.5 Report

Communicate to chat:
- Process is in D state, reason identified
- Device or network endpoint causing the wait
- Device health and latency metrics

```
► If storage device issue → investigate further (SAN, NFS, local disk)
► If network I/O → §8 (Network & Dependency Investigation)
► If resolved → §10 (Summary)
```

---

## 7. File Descriptor Investigation

### 7.1 Count Open Files

```bash
# Current open file count
lsof -p <pid> 2>/dev/null | wc -l

# Breakdown by type
lsof -p <pid> 2>/dev/null | awk '{print $5}' | sort | uniq -c | sort -rn

# What kinds of files?
lsof -p <pid> 2>/dev/null | awk '{print $5, $9}' | head -30
```

### 7.2 Check Against Limits

```bash
# Process-level limits
cat /proc/<pid>/limits | grep "open files"

# System-level limits
ulimit -n      # soft limit
ulimit -Hn     # hard limit
cat /proc/sys/fs/file-nr   # system-wide: allocated / free / max
```

### 7.3 Risk Assessment

```
  open_count / soft_limit:
    < 50%  → normal
    50-80% → elevated, monitor
    > 80%  → critical, approaching exhaustion
    ≥ 100% → process will fail on next open()
```

### 7.4 Identify Leak Pattern

```bash
# Are open files growing?
for i in 1 2 3; do
  echo "$(date +%H:%M:%S) $(lsof -p <pid> 2>/dev/null | wc -l)"
  sleep 10
done

# Common leak patterns:
# - Many sockets in CLOSE_WAIT → application not closing connections
# - Thousands of REG entries to same directory → log rotation issue or temp file leak
# - Many pipe/FIFO entries → subprocess management issue
```

### 7.5 Report

Communicate to chat:
- Open file count vs limits
- File type breakdown
- Growth trend
- Leak pattern if identified

```
► If resolved → §10 (Summary)
► If the open files are network sockets → §8
```

---

## 8. Network & Dependency Investigation

The process may be slow because something it depends on is slow.

### 8.1 Map Connections

```bash
# All network connections for this process
ss -tnp | grep <pid>
lsof -p <pid> -i -n

# Identify remote endpoints
ss -tnp | grep <pid> | awk '{print $5}' | sort -u
```

### 8.2 Classify Dependencies

For each remote endpoint, categorize:

```
  ┌─ Gateway          → trading infrastructure, latency-critical
  ├─ OMS              → order management, state-critical
  ├─ Feed Handler     → market data, throughput-critical
  ├─ Database         → persistence layer
  ├─ Message Bus      → Kafka, MQ, etc.
  └─ Other App/Service → identify and classify
```

### 8.3 Check Connection Health

```bash
# Connection states (look for many CLOSE_WAIT, TIME_WAIT, ESTABLISHED with high recv-q)
ss -tnp | grep <pid> | awk '{print $1}' | sort | uniq -c | sort -rn

# Recv-Q / Send-Q buildup (non-zero = congestion or slow consumer/producer)
ss -tnp | grep <pid> | awk '$2 > 0 || $3 > 0'
```

### 8.4 Jump to Upstream Host

If a remote dependency is identified as the bottleneck:

```bash
# SSH to the remote host
ssh <remote_host>

# Run the same §2 triage on that host
# Recursion: the agent applies this entire runbook to the upstream box
```

### 8.5 Check Monitoring System

```
Before or after SSH-ing to the upstream host:
  - Query monitoring/alerting system for active alerts on that host
  - Check for related alerts across the dependency chain
  - Correlate timestamps of alerts with the onset of the issue

  (Expand with specific monitoring API calls — Grafana, Prometheus,
   Nagios, Datadog, etc. — based on environment)
```

### 8.6 Report

Communicate to chat:
- Dependency map for the affected process
- Which upstream system is the likely bottleneck
- Connection health summary
- Related alerts from monitoring
- Findings from upstream host triage

```
► Continue tracing upstream if needed
► If root cause found → §10 (Summary)
```

---

## 9. Application-Specific Paths

Expand this section per application type. Each entry should define:
- **Log locations**
- **Health check commands**
- **Known failure modes**
- **Restart/recovery procedures** (if agent is authorized)

### 9.1 Gateway

```
Log path:       (define per environment)
Health check:   (define per environment)
Known issues:
  - Connection pool exhaustion
  - Upstream exchange connectivity
  - Certificate expiry
```

### 9.2 OMS (Order Management System)

```
Log path:       (define per environment)
Health check:   (define per environment)
Known issues:
  - State reconciliation failures
  - Database connection pool
  - Message queue backlog
```

### 9.3 Feed Handlers

```
Log path:       (define per environment)
Health check:   (define per environment)
Known issues:
  - Multicast group join failures
  - Sequence number gaps
  - Symbol table reload
  - Slow consumer (kernel buffer overflow)
```

### 9.4 Quant / Strategy Applications

```
Log path:       (define per environment)
Health check:   (define per environment)
Known issues:
  - Model computation spikes
  - Data subscription overload
  - Shared memory segment issues
```

---

## 10. Summary & Reporting

The agent compiles a structured report:

```
┌──────────────────────────────────────────────────────────┐
│  TROUBLESHOOTING SUMMARY                                 │
├──────────────────────────────────────────────────────────┤
│  Host:            <hostname>                             │
│  Timestamp:       <when investigation started>           │
│  Trigger:         <symptom or PID provided>              │
│                                                          │
│  System Snapshot:                                        │
│    CPU cores:     <n>                                    │
│    Load avg:      <1m> / <5m> / <15m>  (ratio: x.xx)    │
│    Memory:        <used> / <total> (<% used>)            │
│    Swap:          <used> / <total>                       │
│                                                          │
│  Offending Process:                                      │
│    PID:           <pid>                                  │
│    Name:          <process name>                         │
│    User:          <owner>                                │
│    %CPU:          <value> (on <n> cores)                 │
│    %MEM:          <value>                                │
│    State:         <state>                                │
│    Open files:    <count> / <limit>                      │
│                                                          │
│  Root Cause:      <brief description>                    │
│  Evidence:        <key findings, log entries, metrics>   │
│  Affected Chain:  <host A → host B → host C>            │
│  Related Alerts:  <from monitoring system>               │
│                                                          │
│  Recommendation:  <next steps or remediation>            │
└──────────────────────────────────────────────────────────┘
```

---

## Appendix A: Quick Reference — Key Commands

| Purpose | Command |
|---|---|
| CPU topology | `lscpu` |
| Load average | `uptime` |
| Top processes | `top -bn1 -o %CPU \| head -20` |
| Memory overview | `free -h` |
| D-state processes | `ps aux \| awk '$8 ~ /D/'` |
| Process details | `ps -p <pid> -o pid,ppid,user,%cpu,%mem,stat,start,time,args` |
| Open file count | `lsof -p <pid> \| wc -l` |
| File descriptor limits | `cat /proc/<pid>/limits \| grep "open files"` |
| I/O stats | `iostat -x 1 3` |
| Process I/O | `cat /proc/<pid>/io` |
| Network connections | `ss -tnp \| grep <pid>` |
| System logs | `journalctl --since "10 minutes ago" --priority=warning` |
| Kernel messages | `dmesg -T \| tail -30` |

## Appendix B: Decision Tree — Visual Summary

```
                          ┌──────────┐
                          │  START   │
                          └────┬─────┘
                               │
                    ┌──── PID given? ────┐
                    │                    │
                    No                  Yes
                    │                    │
              ┌─────▼─────┐        ┌────▼─────┐
              │  §2 Triage │       │ §3 Deep   │
              │  system    │       │   Dive    │
              └─────┬──────┘       └────┬──────┘
                    │                    │
              identify PID          examine state
                    │                    │
                    └────────┬───────────┘
                             │
                   ┌─────────▼──────────┐
                   │  What's the issue? │
                   └─────────┬──────────┘
                             │
            ┌────────┬───────┼────────┬──────────┐
            │        │       │        │          │
         High CPU  High   D-state  High FDs   Nothing
            │       MEM      │        │        obvious
            │        │       │        │          │
         ┌──▼──┐ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐  ┌───▼───┐
         │ §4  │ │ §5  │ │ §6  │ │ §7  │  │  §8   │
         │ CPU │ │ MEM │ │ I/O │ │ FDs │  │Network│
         └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘  └───┬───┘
            │       │       │       │          │
            │       │    ┌──┴──┐    │          │
            │       │  local  network──────────┤
            │       │  disk     │              │
            │       │    │      └──────┬───────┘
            │       │    │             │
            │       │    │     ┌───────▼────────┐
            │       │    │     │ §8 Jump to     │
            │       │    │     │ upstream host  │
            │       │    │     │ + check alerts │
            │       │    │     └───────┬────────┘
            │       │    │             │
            └───────┴────┴─────────────┘
                             │
                     ┌───────▼───────┐
                     │  §10 Summary  │
                     │  & Report     │
                     └───────────────┘
```
