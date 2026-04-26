"""engines/recon/dns.py — Full DNS record enumeration."""

import socket
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_host


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA", "DMARC"]


class DNSLookup(BaseModule):
    name        = "recon/dns"
    description = "Full DNS record enumeration (A, MX, NS, TXT, SOA, CAA...)"

    def __init__(self):
        self.options = {
            "TARGET": Option(required=True, description="Hostname or domain"),
        }
        super().__init__()

    def run(self):
        target = require_host(self.opt("TARGET"))

        dns = self.need_package("dns.resolver", "dnspython")
        import dns.resolver, dns.reversename, dns.exception

        resolver          = dns.resolver.Resolver()
        resolver.timeout  = self._timeout
        resolver.lifetime = self._timeout * 2

        found = False

        for rtype in RECORD_TYPES:
            qname = f"_dmarc.{target}" if rtype == "DMARC" else target
            qtype = "TXT" if rtype == "DMARC" else rtype
            try:
                answers = resolver.resolve(qname, qtype)
                section(f"{rtype} Records")
                for rd in answers:
                    val = str(rd)
                    print(color(f"  → {val}", "cyan"))
                    self.note(f"DNS {rtype}", val)
                found = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.exception.Timeout:
                warn(f"Timeout querying {rtype}")
            except Exception:
                pass

        # Reverse DNS
        try:
            ip  = socket.gethostbyname(target)
            rev = dns.reversename.from_address(ip)
            ptr = str(resolver.resolve(rev, "PTR")[0])
            section("Reverse DNS (PTR)")
            print(color(f"  → {ip} → {ptr}", "cyan"))
            self.note("PTR record", f"{ip} → {ptr}")
            found = True
        except Exception:
            pass

        print()
        if found:
            success("DNS enumeration complete.")
        else:
            warn("No DNS records found.")
