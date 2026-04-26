"""engines/recon/pingsweep.py — OS-aware ping sweep."""

import subprocess
import concurrent.futures
import ipaddress
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn
from core.validator   import require_host_or_cidr
from core.compat      import ping_cmd, get_threads


class PingSweep(BaseModule):
    name        = "recon/pingsweep"
    description = "Discover live hosts in a subnet or check single host"

    def __init__(self):
        self.options = {
            "TARGET":  Option(required=True, description="IP or CIDR range  e.g. 192.168.1.0/24"),
            "THREADS": Option(default=str(get_threads()), description="Concurrent threads", kind="int"),
        }
        super().__init__()

    def _ping(self, ip: str) -> tuple[str, bool]:
        try:
            cmd    = ping_cmd(str(ip))
            result = subprocess.run(cmd, capture_output=True, timeout=3)
            return str(ip), result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return str(ip), False

    def run(self):
        target  = require_host_or_cidr(self.opt("TARGET"))
        threads = int(self.opt("THREADS"))

        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts   = list(network.hosts())
        except ValueError:
            # Single IP
            hosts = [ipaddress.ip_address(target)]

        if len(hosts) > 512:
            warn(f"Large range ({len(hosts)} hosts) — limiting to first 256.")
            hosts = hosts[:256]

        info(f"Sweeping {len(hosts)} host(s)  threads={threads}\n")

        live = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(self._ping, h): h for h in hosts}
            for f in concurrent.futures.as_completed(futures):
                ip, alive = f.result()
                if alive:
                    live.append(ip)
                    print(color(f"  [+] {ip}", "green") + color("  ALIVE", "dark"))

        print()
        if live:
            success(f"{len(live)} live host(s) found.")
            for ip in live:
                self.note(f"Live host: {ip}")
        else:
            warn("No live hosts found.")
