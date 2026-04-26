"""engines/recon/traceroute.py — OS-aware traceroute."""

import subprocess
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, error
from core.validator   import require_host
from core.compat      import trace_cmd, IS_WIN
from core.errors      import DependencyError


class Traceroute(BaseModule):
    name        = "recon/traceroute"
    description = "Map network hops to target"

    def __init__(self):
        self.options = {
            "TARGET": Option(required=True, description="Hostname or IP"),
        }
        super().__init__()

    def run(self):
        target = require_host(self.opt("TARGET"))
        cmd    = trace_cmd(target)
        info(f"Tracing route to {target}  (cmd: {' '.join(cmd)})\n")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            hop = 0
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                hop += 1
                c = "cyan" if hop % 2 == 0 else "white"
                print(color(f"  {line}", c))
            proc.wait()
            print()
            success("Traceroute complete.")

        except FileNotFoundError:
            binary = "tracert" if IS_WIN else "traceroute"
            from core.compat import bin_install_hint
            raise DependencyError(binary, bin_install_hint(binary))
