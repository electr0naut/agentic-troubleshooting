import subprocess
import shlex
import sys
from datetime import datetime

from .config import load_config


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
            full_cmd = (
                f"ssh -o ConnectTimeout={ssh_to} "
                f"-o StrictHostKeyChecking=accept-new {remote} {shlex.quote(cmd)}"
            )

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
