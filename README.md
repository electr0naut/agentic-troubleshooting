# Agentic Troubleshooter

A read-only diagnostic agent that connects to Linux (or macOS) hosts via SSH and systematically investigates performance issues following a structured decision tree. Designed for production trading infrastructure where the investigation itself must not impact the host.

## Requirements

- Python 3.7+ (stdlib only, zero dependencies)
- SSH access to target hosts (for remote mode)
- `lsof`, `ps`, `top`, `iostat` available on the target (standard on RHEL, Ubuntu, Debian, Rocky, Amazon Linux, SUSE)

No `pip install` needed. Clone and run.

## Quick Start

```bash
git clone <repo-url> && cd agentic-troubleshooting

# System-wide triage on localhost (finds the worst offender automatically)
python3 troubleshooter.py

# Investigate a specific PID
python3 troubleshooter.py --pid 12345

# Investigate with a symptom hint (forces specific branches)
python3 troubleshooter.py --pid 12345 --symptom "high memory"

# Remote host via SSH
python3 troubleshooter.py --host prod-server-01 --user ops

# Remote host with symptom
python3 troubleshooter.py --host prod-server-01 --user ops --symptom "slow disk io"
```

## How It Works

The troubleshooter follows a decision tree (documented in `TROUBLESHOOTING_RUNBOOK.md`):

```
START
  |
  +-- PID given? ---> Process Deep-Dive (section 3)
  |
  +-- No PID -------> System-Wide Triage (section 2)
                         |
                         v
                    Identify worst offender
                         |
                         v
                    Process Deep-Dive
                         |
            +--------+---+---+--------+
            |        |       |        |
         High CPU  High   D-state  High FDs  Nothing
            |       MEM      |        |      obvious
            v        v       v        v        v
          sect 4   sect 5  sect 6   sect 7   sect 8
           CPU      MEM     I/O      FDs    Network
```

Each branch runs diagnostic commands, collects evidence, and produces findings with severity levels (info/warning/critical). All findings include the offending PID and process name.

## Safety Guarantees

- **Read-only.** Never kills, restarts, or modifies anything on the target host.
- **No writes to remote.** Zero temp files, no output redirection on the target.
- **Timeout-wrapped.** Every command has a 10-second timeout. strace capped at 5 seconds.
- **Scoped commands.** Always `lsof -p <pid>`, never system-wide `lsof`.
- **5-minute budget.** Escalates if unresolved, doesn't camp on the host.
- **Operator commands only.** When remediation is needed, it gives you the exact command to run yourself.

See section 0 of `TROUBLESHOOTING_RUNBOOK.md` for the full safety specification.

## Symptom Hints

The `--symptom` flag forces investigation branches even when metrics don't cross thresholds. Keywords:

| Keyword | Branch triggered |
|---|---|
| `cpu` | CPU investigation |
| `memory`, `mem` | Memory investigation |
| `io`, `disk`, `iowait` | I/O investigation |
| `fd`, `file`, `descriptor` | File descriptor investigation |
| `network`, `net`, `connection`, `slow` | Network investigation |

Multiple keywords can match: `--symptom "slow disk io"` triggers both I/O and network branches.

## Running the Test Suite

The test suite launches 5 safe dummy processes and runs the troubleshooter against each:

```bash
python3 run_all_tests.py
```

| Scenario | Dummy | What it triggers |
|---|---|---|
| CPU Saturation | `cpu_burner.py` — tight loop on one core | CPU branch (auto-detected via %CPU > 50%) |
| Memory Pressure | `mem_hog.py` — allocates 512 MB | Memory branch (symptom-hinted) |
| I/O Pressure | `io_slowpoke.py` — fsync loop to /tmp | I/O branch (symptom-hinted) |
| FD Exhaustion | `fd_leaker.py` — opens 85% of a 256 FD limit | FD branch (auto-detected via ratio) |
| Network Congestion | `net_congestion.py` — slow-consumer TCP | Network branch (auto + symptom) |

All dummies are safe: they self-limit resource usage, write only to /tmp, use only loopback networking, and clean up on SIGTERM. The test runner terminates all dummies automatically after each scenario.

You can also run dummies individually:

```bash
# Start a dummy in the background
python3 cpu_burner.py &

# Run the troubleshooter against it
python3 troubleshooter.py --pid $!
```

## Platform Support

| Platform | Status |
|---|---|
| RHEL / CentOS / Rocky 8+ | Supported |
| Ubuntu 20.04+ | Supported |
| Debian 11+ | Supported |
| Amazon Linux 2+ | Supported |
| SUSE / openSUSE 15+ | Supported |
| macOS 12+ (Apple Silicon / Intel) | Supported |

The troubleshooter detects the OS at runtime and uses platform-appropriate commands:

| Capability | Linux | macOS |
|---|---|---|
| CPU topology | `nproc` | `sysctl -n hw.logicalcpu` |
| Memory overview | `free -h` | `vm_stat` + `sysctl hw.memsize` |
| Process state | `ps stat` column (D = I/O wait) | `ps state` column (U = uninterruptible) |
| I/O stats | `iostat -x`, `/proc/<pid>/io` | `iostat -d` |
| FD limits | `/proc/<pid>/limits` | `launchctl limit maxfiles` |
| Swap | `/proc/meminfo`, `/proc/<pid>/status` | `sysctl vm.swapusage` |
| Network | `ss -tnp` | `netstat -an -p tcp` + `lsof -i` |
| System logs | `journalctl`, `dmesg` | `log show` |

## Project Structure

```
agentic-troubleshooting/
  troubleshooter.py          # The agent — run this
  TROUBLESHOOTING_RUNBOOK.md # Decision tree documentation
  run_all_tests.py           # Test runner for all 5 scenarios
  cpu_burner.py              # Test dummy: CPU saturation
  mem_hog.py                 # Test dummy: memory pressure
  io_slowpoke.py             # Test dummy: I/O pressure
  fd_leaker.py               # Test dummy: FD exhaustion
  net_congestion.py          # Test dummy: network congestion
```
