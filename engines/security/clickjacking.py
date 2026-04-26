"""engines/security/clickjacking.py — Clickjacking vulnerability tester."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url
from core.errors      import NetworkError

PAGES = ["", "login", "register", "dashboard", "settings", "admin", "profile", "payment"]


class ClickjackTester(BaseModule):
    name        = "security/clickjacking"
    description = "Check if site pages can be embedded in an iframe"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="URL or domain")}
        super().__init__()

    def _check(self, session, url: str) -> tuple[bool, str]:
        """Returns (vulnerable, protection)."""
        try:
            resp = session.get(url, timeout=self._timeout)
            h    = {k.lower(): v.lower() for k, v in resp.headers.items()}

            xfo = h.get("x-frame-options", "")
            csp = h.get("content-security-policy", "")

            if xfo in ("deny", "sameorigin"):
                return False, f"X-Frame-Options: {xfo.upper()}"
            if "frame-ancestors" in csp:
                fa = [p.strip() for p in csp.split(";") if "frame-ancestors" in p]
                return False, fa[0] if fa else "CSP frame-ancestors"

            return True, "No framing protection"
        except Exception:
            return False, "unreachable"

    def run(self):
        requests   = self.need_package("requests")
        target     = require_url(self.opt("TARGET"))
        session    = requests.Session()
        session.headers["User-Agent"] = "ReconCLI/3.0"

        info(f"Checking {len(PAGES)} page(s) for clickjacking...\n")
        vulnerable = []

        for page in PAGES:
            url  = f"{target.rstrip('/')}/{page}".rstrip("/")
            label = f"/{page}" if page else "/ (home)"
            vuln, protection = self._check(session, url)

            row = color(f"  {label:<35}", "cyan")
            if vuln:
                vulnerable.append(url)
                print(row + color("[✘] VULNERABLE", "red"))
            else:
                print(row + color(f"[✔] {protection}", "green"))

        print()
        if vulnerable:
            poc = vulnerable[0]
            self.high(f"{len(vulnerable)} page(s) vulnerable to clickjacking")
            section("Proof of Concept")
            print(color(f'  <iframe src="{poc}" style="opacity:0.01;', "yellow"))
            print(color(f'          position:absolute;top:0;left:0;width:100%;height:100%">', "yellow"))
            print(color(f'  </iframe>', "yellow"))
            section("Fix (add to Netlify _headers or server config)")
            print(color("  X-Frame-Options: DENY", "cyan"))
            print(color("  # OR", "dark"))
            print(color("  Content-Security-Policy: frame-ancestors 'none'", "cyan"))
        else:
            success("All pages protected against clickjacking.")
