"""§8 Network & Dependency Investigation"""
import re


def investigate(ts, pid):
    if ts.over_budget():
        return
    print(f"\n── §8 Network & Dependency Investigation — PID {pid} ──\n")

    c = ts.cfg
    out = ts.runner.run(f"lsof -p {pid} -i -n -P 2>/dev/null")
    pn = ts._pn(pid)
    if not out.strip():
        print("  No network connections found.")
        ts._finding("network", "info", f"{pn} has no active network connections")
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
        ts._finding("network", "critical",
                     f"{pn} has {total_conns} connections — very high, possible connection leak")
    elif total_conns >= c["net_conn_count_warning"]:
        ts._finding("network", "warning", f"{pn} has {total_conns} connections — elevated")
    else:
        ts._finding("network", "info", f"{pn} has {total_conns} connection(s)")

    close_wait = states.get("CLOSE_WAIT", 0)
    if close_wait > c["net_close_wait_warning"]:
        ts._finding("network", "warning",
                     f"{pn} has {close_wait} connections in CLOSE_WAIT — "
                     f"remote side closed but application hasn't")

    if ts.runner.is_darwin:
        local_ports = set()
        for line in conn_lines:
            port_match = re.search(r'(?:localhost|[\d.]+|\*):(\d+)', line)
            if port_match:
                local_ports.add(port_match.group(1))

        if local_ports:
            max_ns = c["out_max_netstat_lines"]
            print(f"\n  Checking queue depth for {len(local_ports)} local ports...")
            netstat_out = ts.runner.run(f"netstat -an -p tcp 2>/dev/null | head -{max_ns}")
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
                ts._finding("network", "warning",
                             f"{pn} has {len(congested)} congested connections (non-zero queues)")
                for item in congested[:5]:
                    print(f"    {item}")
            else:
                print("  No queue congestion detected.")
    else:
        out = ts.runner.run(f"ss -tnp 2>/dev/null | grep {pid}")
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
                ts._finding("network", "warning",
                             f"{pn} has {len(queued)} connections with non-zero queue depth — possible congestion")
                for q in queued[:5]:
                    print(f"    {q}")

    if remote_endpoints:
        print(f"\n  Top remote endpoints:")
        for ip, count in sorted(remote_endpoints.items(), key=lambda x: -x[1])[:5]:
            print(f"    {ip:>20}: {count} connection(s)")
        top_ip, top_count = max(remote_endpoints.items(), key=lambda x: x[1])
        if top_count > c["net_endpoint_conc_warning"]:
            ts._finding("network", "info",
                         f"{pn} highest concentration: {top_count} connections to {top_ip}")

    ts._recommend(
        f"PID {pid} has {total_conns} network connections. "
        f"Operator should inspect with:  lsof -p {pid} -i -n -P  "
        f"For queue depth:  netstat -an -p tcp  (macOS) or  ss -tnp  (Linux). "
        f"Do NOT kill or restart the process from this agent."
    )
