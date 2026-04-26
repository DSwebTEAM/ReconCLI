"""engines/security/ssl.py — SSL/TLS certificate and configuration check."""

import ssl
import socket
import datetime
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_host
from core.errors      import NetworkError, SSLError as ReconSSLError


class SSLCheck(BaseModule):
    name        = "security/ssl"
    description = "Validate SSL certificate, expiry, and TLS version"

    def __init__(self):
        self.options = {
            "TARGET": Option(required=True, description="Hostname (no https://)"),
            "PORT":   Option(default="443", description="Port", kind="int"),
        }
        super().__init__()

    def run(self):
        host = require_host(self.opt("TARGET"))
        port = int(self.opt("PORT"))
        ctx  = ssl.create_default_context()

        info(f"Connecting to {host}:{port}...\n")

        try:
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert   = ssock.getpeercert()
                    cipher = ssock.cipher()
                    ver    = ssock.version()
        except ssl.SSLCertVerificationError as e:
            self.critical("SSL verification failed", str(e))
            raise ReconSSLError(str(e))
        except ssl.SSLError as e:
            raise ReconSSLError(str(e))
        except (ConnectionRefusedError, OSError) as e:
            raise NetworkError(f"Cannot connect to {host}:{port} — {e}")

        # ── Certificate ───────────────────────────────────────────
        section("Certificate")
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))

        print(color(f"  {'CN':<20}: ", "dark") + color(subject.get("commonName", "N/A"), "cyan"))
        print(color(f"  {'Issued by':<20}: ", "dark") + color(issuer.get("organizationName", "N/A"), "cyan"))

        not_after = cert.get("notAfter", "")
        if not_after:
            expiry    = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            c = "green" if days_left > 30 else "yellow" if days_left > 7 else "red"
            print(color(f"  {'Expires':<20}: ", "dark") +
                  color(f"{not_after}  ({days_left}d left)", c))
            if days_left < 7:
                self.critical(f"Certificate expires in {days_left} days!", not_after)
            elif days_left < 30:
                self.high(f"Certificate expires in {days_left} days", not_after)
            else:
                self.note("Certificate expiry", f"{days_left} days")

        # SANs
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        if sans:
            section(f"SANs ({len(sans)})")
            for san in sans[:10]:
                print(color(f"  → {san}", "cyan"))

        # Self-signed
        if subject == issuer:
            self.critical("Self-signed certificate", "Not trusted by browsers")

        # ── TLS ───────────────────────────────────────────────────
        section("TLS")
        cipher_name = cipher[0] if cipher else "Unknown"
        ver_c = "green" if "1.3" in ver else "yellow" if "1.2" in ver else "red"
        print(color(f"  {'Protocol':<20}: ", "dark") + color(ver, ver_c))
        print(color(f"  {'Cipher':<20}: ", "dark") + color(cipher_name, "cyan"))
        print(color(f"  {'Bits':<20}: ", "dark") + color(str(cipher[2] if cipher else 0), "cyan"))

        if "1.0" in ver or "1.1" in ver:
            self.critical("TLS 1.0/1.1 in use — insecure, upgrade to TLS 1.3")
        elif "1.2" in ver:
            self.low("TLS 1.2 — consider upgrading to TLS 1.3")
        else:
            success("TLS 1.3 — excellent!")

        print()
        success("SSL check complete.")
