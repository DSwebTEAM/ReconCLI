"""engines/recon/cloudscan.py — Detect cloud provider, storage buckets, CDN."""

import socket
import re
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_host, resolve
from core.errors      import NetworkError

# Cloud provider detection by IP range prefixes / CNAME patterns
CLOUD_CNAMES = {
    "netlify":      ["netlify.app", "netlify.com"],
    "vercel":       ["vercel.app", "now.sh"],
    "cloudflare":   ["cloudflare"],
    "aws":          ["amazonaws.com", "cloudfront.net", "awsglobalaccelerator.com"],
    "gcp":          ["googleusercontent.com", "googleapis.com", "run.app"],
    "azure":        ["azurewebsites.net", "windows.net", "azure.com"],
    "github":       ["github.io", "githubusercontent.com"],
    "heroku":       ["herokuapp.com"],
    "render":       ["onrender.com"],
    "railway":      ["railway.app"],
    "fly.io":       ["fly.dev", "fly.io"],
}

# Common open bucket patterns
BUCKET_PATTERNS = [
    "s3.amazonaws.com",
    "storage.googleapis.com",
    "blob.core.windows.net",
]

S3_BUCKET_NAMES = [
    "{domain}", "{domain}-backup", "{domain}-static",
    "{domain}-assets", "{domain}-media", "{domain}-files",
    "{domain}-dev", "{domain}-staging",
]


class CloudScan(BaseModule):
    name        = "recon/cloudscan"
    description = "Detect cloud provider, CDN, and misconfigured storage buckets"

    def __init__(self):
        self.options = {
            "TARGET": Option(required=True, description="Domain or IP"),
        }
        super().__init__()

    def _detect_provider(self, requests, target: str, ip: str) -> str:
        """Detect hosting provider via CNAME, headers, IP."""
        # Check CNAME chain
        try:
            import dns.resolver
            answers = dns.resolver.resolve(target, "CNAME")
            cname   = str(answers[0]).lower()
            for provider, patterns in CLOUD_CNAMES.items():
                if any(p in cname for p in patterns):
                    return provider
        except Exception:
            pass

        # Check via HTTP headers
        try:
            resp = requests.get(f"https://{target}", timeout=self._timeout,
                                headers={"User-Agent": "ReconCLI/3.0"})
            headers_str = str(resp.headers).lower()
            for provider, patterns in CLOUD_CNAMES.items():
                if any(p in headers_str for p in patterns):
                    return provider
            server = resp.headers.get("Server", "").lower()
            via    = resp.headers.get("Via",    "").lower()
            if "cloudflare" in server or "cloudflare" in via:
                return "cloudflare"
        except Exception:
            pass

        return "unknown"

    def _check_s3_bucket(self, requests, name: str) -> tuple[bool, str]:
        """Check if an S3 bucket exists and is publicly accessible."""
        url = f"https://{name}.s3.amazonaws.com"
        try:
            resp = requests.get(url, timeout=5,
                                headers={"User-Agent": "ReconCLI/3.0"})
            if resp.status_code == 200:
                return True, "PUBLIC — bucket is open!"
            elif resp.status_code == 403:
                return True, "EXISTS but access denied (private)"
            elif resp.status_code == 404:
                return False, ""
        except Exception:
            pass
        return False, ""

    def run(self):
        requests = self.need_package("requests")
        target   = require_host(self.opt("TARGET"))
        ip       = resolve(target)

        info(f"Resolved {target} → {ip}")

        # Detect cloud provider
        info("Detecting cloud provider...\n")
        provider = self._detect_provider(requests, target, ip)

        section("Cloud Provider")
        c = "green" if provider != "unknown" else "dark"
        print(color(f"  Provider : {provider.upper()}", c))
        self.note("Cloud provider", provider)

        if provider != "unknown":
            info(f"Detected: {provider}")

        # S3 bucket enumeration
        section("S3 Bucket Check")
        base = target.split(".")[0]
        bucket_names = [p.format(domain=base) for p in S3_BUCKET_NAMES]

        info(f"Checking {len(bucket_names)} common bucket name(s)...\n")
        found_any = False
        for name in bucket_names:
            exists, status = self._check_s3_bucket(requests, name)
            if exists:
                found_any = True
                if "PUBLIC" in status:
                    self.critical(f"Open S3 bucket: {name}", status)
                else:
                    self.note(f"S3 bucket exists: {name}", status)
                print(color(f"  [+] {name}", "red" if "PUBLIC" in status else "yellow") +
                      color(f"  {status}", "dark"))

        if not found_any:
            success("No exposed S3 buckets found.")

        # Cloudflare-specific checks
        if provider == "cloudflare":
            section("Cloudflare Notes")
            info("Site is behind Cloudflare — real IP may be hidden.")
            info("Use: recon/passivedns or recon/wayback to find origin IP leaks.")

        print()
        success("Cloud scan complete.")
