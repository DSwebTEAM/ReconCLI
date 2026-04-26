"""engines/recon/passivedns.py — Historical DNS records via passive sources."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_host
from core.errors      import NetworkError


class PassiveDNS(BaseModule):
    name        = "recon/passivedns"
    description = "Historical DNS records (no active probing)"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="Domain to query")}
        super().__init__()

    def run(self):
        requests = self.need_package("requests")
        target   = require_host(self.opt("TARGET"))
        info(f"Querying passive DNS for {target}...\n")

        sources = [
            ("HackerTarget", f"https://api.hackertarget.com/hostsearch/?q={target}"),
        ]

        all_records = []
        for name, url in sources:
            try:
                resp = requests.get(url, timeout=self._timeout,
                                    headers={"User-Agent": "ReconCLI/3.0"})
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    lines = [l.strip() for l in resp.text.strip().split("\n") if l.strip()]
                    section(f"Source: {name}")
                    for line in lines:
                        print(color(f"  → {line}", "cyan"))
                        all_records.append(line)
                        self.note("Passive DNS record", line)
                else:
                    warn(f"{name}: {resp.text[:80]}")
            except Exception as e:
                warn(f"{name} failed: {e}")

        print()
        if all_records:
            success(f"{len(all_records)} passive DNS record(s) found.")
        else:
            warn("No passive DNS records found.")
