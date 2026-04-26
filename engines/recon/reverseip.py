"""engines/recon/reverseip.py — Find all domains hosted on an IP."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_host, resolve
from core.errors      import NetworkError


class ReverseIP(BaseModule):
    name        = "recon/reverseip"
    description = "Find all domains hosted on the same IP"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="IP or hostname")}
        super().__init__()

    def run(self):
        requests = self.need_package("requests")
        target   = require_host(self.opt("TARGET"))
        ip       = resolve(target)
        info(f"Resolved {target} → {ip}\n")

        try:
            resp = requests.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                timeout=self._timeout,
                headers={"User-Agent": "ReconCLI/3.0"}
            )
            text = resp.text.strip()
        except Exception as e:
            raise NetworkError(f"Reverse IP lookup failed: {e}")

        if "error" in text.lower() or "API count" in text:
            warn(f"API response: {text}")
            return

        domains = [d.strip() for d in text.split("\n") if d.strip()]
        section(f"Domains on {ip}")

        if not domains:
            warn("No domains found on this IP.")
            return

        for d in domains:
            print(color(f"  → {d}", "cyan"))
            self.note("Co-hosted domain", d)

        print()
        success(f"{len(domains)} domain(s) on this IP.")

        if len(domains) > 50:
            info("Shared hosting — many domains on same IP (Netlify/Vercel style).")
