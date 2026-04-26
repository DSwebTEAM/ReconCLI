"""engines/analysis/fingerprint.py — Tech stack fingerprinting."""

import re
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_url
from core.errors      import NetworkError

SIGNATURES = [
    # (category, name, detection_fn)
    # Headers
    ("Server",    "Nginx",       lambda h, b: "nginx"       in h.get("server","").lower()),
    ("Server",    "Apache",      lambda h, b: "apache"      in h.get("server","").lower()),
    ("Server",    "Cloudflare",  lambda h, b: "cloudflare"  in h.get("server","").lower()),
    ("Runtime",   "PHP",         lambda h, b: "php"         in h.get("x-powered-by","").lower()),
    ("Runtime",   "ASP.NET",     lambda h, b: "asp.net"     in h.get("x-powered-by","").lower()),
    ("Runtime",   "Express",     lambda h, b: "express"     in h.get("x-powered-by","").lower()),
    # Body
    ("Framework", "React",       lambda h, b: "__REACT" in b or "react.development" in b or "_reactRootContainer" in b),
    ("Framework", "Vue.js",      lambda h, b: "vue.min.js" in b or "__vue__" in b or "data-v-" in b),
    ("Framework", "Next.js",     lambda h, b: "__NEXT_DATA__" in b or "_next/static" in b),
    ("Framework", "Nuxt.js",     lambda h, b: "__NUXT__" in b or "_nuxt/" in b),
    ("Framework", "Angular",     lambda h, b: "ng-version" in b or "angular.min.js" in b),
    ("Framework", "Svelte",      lambda h, b: "__svelte" in b),
    ("CMS",       "WordPress",   lambda h, b: "wp-content" in b or "wp-includes" in b),
    ("CMS",       "Ghost",       lambda h, b: "ghost.io" in b or "content/themes/ghost" in b),
    ("CDN",       "Netlify",     lambda h, b: "netlify" in h.get("server","").lower() or "x-nf-request-id" in h),
    ("CDN",       "Vercel",      lambda h, b: "x-vercel-id" in h),
    ("CDN",       "Cloudflare",  lambda h, b: "cf-ray" in h),
    ("Analytics", "Google Analytics", lambda h, b: "gtag(" in b or "google-analytics.com" in b),
    ("Analytics", "Plausible",   lambda h, b: "plausible.io" in b),
]


class Fingerprint(BaseModule):
    name        = "analysis/fingerprint"
    description = "Detect tech stack — server, framework, CMS, CDN, analytics"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="URL or domain")}
        super().__init__()

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))

        try:
            resp = requests.get(target, timeout=self._timeout,
                                headers={"User-Agent": "ReconCLI/3.0"},
                                allow_redirects=True)
        except Exception as e:
            raise NetworkError(str(e))

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body    = resp.text

        detected = {}
        for category, name, fn in SIGNATURES:
            try:
                if fn(headers, body):
                    detected.setdefault(category, []).append(name)
            except Exception:
                pass

        if not detected:
            warn("No known technologies detected.")
            return

        section("Detected Technologies")
        for category, techs in detected.items():
            print(color(f"  {category:<14}: ", "dark") +
                  color(", ".join(techs), "cyan"))
            for t in techs:
                self.note(f"Tech: {category}", t)

        # Version hints from headers
        section("Version Hints")
        for h in ["Server", "X-Powered-By", "X-Generator", "X-Runtime", "X-AspNet-Version"]:
            if h.lower() in headers:
                val = headers[h.lower()]
                print(color(f"  {h:<22}: ", "dark") + color(val, "yellow"))
                self.medium(f"{h} exposed", val)

        print()
        success("Fingerprint complete.")
