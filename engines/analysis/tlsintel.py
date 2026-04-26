"""engines/analysis/tlsintel.py — Deep TLS/SSL intelligence."""

import ssl
import socket
import datetime
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_host
from core.errors      import NetworkError, SSLError as ReconSSLError


WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
]

CIPHER_GRADE = {
    "TLS_AES_256_GCM_SHA384":       "A+",
    "TLS_CHACHA20_POLY1305_SHA256": "A+",
    "TLS_AES_128_GCM_SHA256":       "A",
    "ECDHE-RSA-AES256-GCM-SHA384":  "A",
    "ECDHE-RSA-AES128-GCM-SHA256":  "A",
    "ECDHE-RSA-AES256-SHA384":      "B",
    "ECDHE-RSA-AES128-SHA256":      "B",
    "AES256-SHA":                   "C",
    "AES128-SHA":                   "C",
}


class TLSIntel(BaseModule):
    name        = "analysis/tlsintel"
    description = "Deep TLS analysis — cert chain, ciphers, HSTS preload, expiry"

    def __init__(self):
        self.options = {
            "TARGET": Option(required=True, description="Hostname (no https://)"),
            "PORT":   Option(default="443", description="Port", kind="int"),
        }
        super().__init__()

    def _get_cert(self, host: str, port: int) -> tuple[dict, tuple, str]:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert   = ssock.getpeercert()
                    cipher = ssock.cipher()          # (name, protocol, bits)
                    ver    = ssock.version()
                    return cert, cipher, ver
        except ssl.SSLCertVerificationError as e:
            raise ReconSSLError(str(e))
        except ssl.SSLError as e:
            raise ReconSSLError(str(e))
        except (ConnectionRefusedError, OSError) as e:
            raise NetworkError(f"Cannot connect to {host}:{port} — {e}")

    def _check_hsts_preload(self, requests, host: str) -> str:
        """Check hstspreload.org for preload status."""
        try:
            resp = requests.get(
                f"https://hstspreload.org/api/v2/status?domain={host}",
                timeout=5
            )
            data   = resp.json()
            status = data.get("status", "unknown")
            return status
        except Exception:
            return "unknown"

    def run(self):
        requests = self.need_package("requests")
        host     = require_host(self.opt("TARGET"))
        port     = int(self.opt("PORT"))

        info(f"Connecting to {host}:{port}...\n")

        cert, cipher, tls_ver = self._get_cert(host, port)

        # ── Certificate ───────────────────────────────────────────
        section("Certificate")
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))

        cn  = subject.get("commonName", "N/A")
        org = issuer.get("organizationName", "N/A")

        print(color(f"  {'Common Name':<22}: ", "dark") + color(cn,  "cyan"))
        print(color(f"  {'Issuer':<22}: ", "dark") + color(org, "cyan"))

        # Expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry    = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            exp_c     = "green" if days_left > 30 else "yellow" if days_left > 7 else "red"
            print(color(f"  {'Expires':<22}: ", "dark") +
                  color(f"{not_after}  ({days_left}d left)", exp_c))
            if days_left < 30:
                self.high(f"Certificate expires in {days_left} days", not_after)
            elif days_left < 7:
                self.critical("Certificate expires very soon!", not_after)
            else:
                self.note("Certificate expiry", f"{days_left} days")

        # SANs
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        if sans:
            section(f"Subject Alt Names ({len(sans)})")
            for san in sans:
                print(color(f"  → {san}", "cyan"))

        # ── TLS config ────────────────────────────────────────────
        section("TLS Configuration")
        cipher_name = cipher[0] if cipher else "Unknown"
        bits        = cipher[2] if cipher else 0

        ver_c = "green" if "1.3" in tls_ver else "yellow" if "1.2" in tls_ver else "red"
        print(color(f"  {'Protocol':<22}: ", "dark") + color(tls_ver, ver_c))
        print(color(f"  {'Cipher':<22}: ", "dark") + color(cipher_name, "cyan"))
        print(color(f"  {'Key bits':<22}: ", "dark") + color(str(bits), "cyan"))

        grade = CIPHER_GRADE.get(cipher_name, "?")
        print(color(f"  {'Cipher grade':<22}: ", "dark") + color(grade, "green" if grade in ("A+","A") else "yellow"))

        if any(w in cipher_name for w in WEAK_CIPHERS):
            self.critical("Weak cipher in use", cipher_name)
        if "1.0" in tls_ver or "1.1" in tls_ver:
            self.high("Outdated TLS version", tls_ver)
        elif "1.2" in tls_ver:
            self.low("TLS 1.2 — consider upgrading to TLS 1.3")

        # ── HSTS preload ──────────────────────────────────────────
        section("HSTS Preload Status")
        preload = self._check_hsts_preload(requests, host)
        preload_c = "green" if preload == "preloaded" else "yellow"
        print(color(f"  Status: {preload}", preload_c))
        if preload != "preloaded":
            self.low("Not on HSTS preload list", f"Submit at https://hstspreload.org")

        # ── Cert self-signed check ────────────────────────────────
        if subject == issuer:
            self.critical("Self-signed certificate", "Not trusted by browsers")

        print()
        success("TLS intelligence complete.")
