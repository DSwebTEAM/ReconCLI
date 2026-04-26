"""engines/analysis/shield.py — Detect WAF, CDN, and firewall presence."""

import re
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_url
from core.errors      import NetworkError

# Detection rules: (name, check_fn)
# check_fn receives (headers_dict_lower, body_lower, status_code)
SHIELDS = [
    ("Cloudflare",
     lambda h, b, s: "cf-ray" in h or "cloudflare" in h.get("server","") or "__cf_bm" in b),

    ("Netlify",
     lambda h, b, s: "x-nf-request-id" in h or "netlify" in h.get("server","").lower()),

    ("Vercel",
     lambda h, b, s: "x-vercel-id" in h or "x-vercel-cache" in h),

    ("AWS WAF",
     lambda h, b, s: "awswaf" in b or "x-amzn-requestid" in h or "x-amz-apigw-id" in h),

    ("AWS CloudFront",
     lambda h, b, s: "x-amz-cf-id" in h or "cloudfront.net" in h.get("via","")),

    ("Akamai",
     lambda h, b, s: "akamai" in h.get("server","").lower() or "x-akamai-transformed" in h or "akamaighost" in b),

    ("Fastly",
     lambda h, b, s: "x-fastly-request-id" in h or "fastly" in h.get("via","").lower()),

    ("Sucuri",
     lambda h, b, s: "x-sucuri-id" in h or "sucuri" in h.get("server","").lower()),

    ("Imperva / Incapsula",
     lambda h, b, s: "x-iinfo" in h or "incap_ses" in b or "visid_incap" in b),

    ("ModSecurity",
     lambda h, b, s: "mod_security" in b or "modsecurity" in b or
                     (s == 403 and "not acceptable" in b)),

    ("Nginx",
     lambda h, b, s: h.get("server","").lower().startswith("nginx")),

    ("Apache",
     lambda h, b, s: h.get("server","").lower().startswith("apache")),

    ("GitHub Pages",
     lambda h, b, s: "x-github-request-id" in h),
]

# WAF evasion test payloads — to see if WAF blocks them
WAF_PROBES = [
    ("SQLi probe",   "?id=1'%20OR%20'1'='1"),
    ("XSS probe",    "?q=<script>alert(1)</script>"),
    ("Path traversal","/../../../etc/passwd"),
]


class ShieldDetect(BaseModule):
    name        = "analysis/shield"
    description = "Detect WAF, CDN, and firewall protecting the target"

    def __init__(self):
        self.options = {
            "TARGET":    Option(required=True,   description="URL or domain"),
            "WAF_PROBE": Option(default="false", description="Send WAF evasion probes (true/false)", kind="bool"),
        }
        super().__init__()

    def run(self):
        requests  = self.need_package("requests")
        target    = require_url(self.opt("TARGET"))
        waf_probe = bool(self.opt("WAF_PROBE"))

        info(f"Scanning for shields on {target}...\n")

        try:
            resp = requests.get(
                target, timeout=self._timeout,
                headers={"User-Agent": "ReconCLI/3.0"},
                allow_redirects=True
            )
        except Exception as e:
            raise NetworkError(str(e))

        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body    = resp.text.lower()
        status  = resp.status_code

        section("Shield Detection")
        detected = []
        for name, fn in SHIELDS:
            try:
                if fn(headers, body, status):
                    detected.append(name)
                    print(color(f"  [✔] Detected: {name}", "green"))
                    self.note("Shield detected", name)
            except Exception:
                pass

        if not detected:
            warn("No known WAF/CDN detected.")
            info("Site may be unprotected or using an unknown provider.")

        # WAF probe test
        if waf_probe:
            section("WAF Probe Tests")
            info("Sending test payloads to check WAF blocking...\n")

            for label, payload in WAF_PROBES:
                probe_url = target.rstrip("/") + payload
                try:
                    r = requests.get(
                        probe_url, timeout=self._timeout,
                        headers={"User-Agent": "ReconCLI/3.0"}
                    )
                    if r.status_code in (403, 406, 429, 503):
                        print(color(f"  [✔] {label:<30}", "green") +
                              color(f" Blocked (HTTP {r.status_code})", "dark"))
                        self.note(f"WAF blocks {label}")
                    elif r.status_code == 200:
                        print(color(f"  [✘] {label:<30}", "red") +
                              color(f" NOT blocked (HTTP 200) — payload passed through!", "yellow"))
                        self.high(f"WAF did not block {label}", probe_url)
                    else:
                        print(color(f"  [?] {label:<30}", "dark") +
                              color(f" HTTP {r.status_code}", "dark"))
                except Exception as e:
                    warn(f"{label}: request failed — {e}")

        print()
        if detected:
            success(f"{len(detected)} shield(s) detected: {', '.join(detected)}")
        else:
            warn("No shields detected — consider adding WAF/CDN protection.")
