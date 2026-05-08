"""
Agentic troubleshooter — entry point.

Connects to a host via SSH (or runs locally) and diagnoses performance issues
following the decision tree in TROUBLESHOOTING_RUNBOOK.md. All commands are
read-only, timeout-wrapped, and scoped per §0 guidelines.

CRITICAL CONSTRAINT: The agent NEVER kills, restarts, or otherwise modifies
processes or network connections. It only observes and reports.
"""
import argparse

from modules.config import load_config
from modules.runner import CommandRunner
from modules.core import Troubleshooter


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
