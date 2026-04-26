"""engines/recon/asn.py — ASN lookup, find all IP ranges owned by a target org."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_host, resolve
from core.errors      import NetworkError


class ASNLookup(BaseModule):
    name        = "recon/asn"
    description = "Find ASN and all IP ranges owned by a domain/org"

    def __init__(self):
        self.options = {
            "TARGET": Option(required=True, description="IP, hostname, or ASN (e.g. AS13335)"),
        }
        super().__init__()

    def _lookup_ip(self, requests, ip: str) -> dict:
        resp = requests.get(
            f"https://api.hackertarget.com/aslookup/?q={ip}",
            timeout=self._timeout,
            headers={"User-Agent": "ReconCLI/3.0"}
        )
        # Response: "1.1.1.0/24","AS13335","CLOUDFLARENET","US"
        text = resp.text.strip().strip('"')
        parts = [p.strip().strip('"') for p in text.split(",")]
        if len(parts) >= 4:
            return {"cidr": parts[0], "asn": parts[1], "org": parts[2], "country": parts[3]}
        return {}

    def _lookup_asn(self, requests, asn: str) -> list:
        resp = requests.get(
            f"https://api.hackertarget.com/aslookup/?q={asn}",
            timeout=self._timeout,
            headers={"User-Agent": "ReconCLI/3.0"}
        )
        return [l.strip() for l in resp.text.strip().split("\n") if l.strip()]

    def run(self):
        requests = self.need_package("requests")
        target   = self.opt("TARGET").strip()

        # Direct ASN query
        if target.upper().startswith("AS"):
            info(f"Querying IP ranges for {target}...\n")
            try:
                ranges = self._lookup_asn(requests, target)
            except Exception as e:
                raise NetworkError(f"ASN lookup failed: {e}")
            section(f"IP Ranges for {target}")
            for r in ranges:
                print(color(f"  → {r}", "cyan"))
                self.note("IP range", r)
            print()
            success(f"{len(ranges)} IP range(s) found.")
            return

        # IP/hostname query
        from core.validator import require_host
        host = require_host(target)
        ip   = resolve(host)
        info(f"Resolved {host} → {ip}")
        info("Looking up ASN...\n")

        try:
            data = self._lookup_ip(requests, ip)
        except Exception as e:
            raise NetworkError(f"ASN lookup failed: {e}")

        if not data:
            warn("No ASN data returned.")
            return

        section("ASN Info")
        for label, value in data.items():
            print(color(f"  {label.upper():<10}: ", "dark") + color(value, "cyan"))
            self.note(label.upper(), value)

        # Get all ranges for this ASN
        if data.get("asn"):
            info(f"\nFetching all IP ranges for {data['asn']}...")
            try:
                ranges = self._lookup_asn(requests, data["asn"])
                section(f"All IP Ranges ({data['asn']})")
                for r in ranges:
                    print(color(f"  → {r}", "cyan"))
                    self.note("IP range", r)
                success(f"{len(ranges)} range(s) in {data['asn']}.")
            except Exception:
                warn("Could not fetch full ASN range list.")
