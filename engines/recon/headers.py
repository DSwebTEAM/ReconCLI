"""engines/recon/headers.py — HTTP headers grab and quick security check."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_url
from core.errors      import NetworkError

SEC_HEADERS = {
    "Strict-Transport-Security": ("HSTS",           "critical"),
    "Content-Security-Policy":   ("CSP",            "critical"),
    "X-Frame-Options":           ("Clickjacking",   "high"),
    "X-Content-Type-Options":    ("MIME sniffing",  "medium"),
    "Referrer-Policy":           ("Referrer",       "medium"),
    "Permissions-Policy":        ("Feature policy", "low"),
}
INFO_LEAKING = ["Server","X-Powered-By","X-AspNet-Version","X-Generator","Via"]


class HeadersGrab(BaseModule):
    name        = "recon/headers"
    description = "Full HTTP headers grab with security analysis"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="URL or domain")}
        super().__init__()

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))

        try:
            resp = requests.get(target, timeout=self._timeout, allow_redirects=True,
                                headers={"User-Agent": "ReconCLI/3.0"})
        except requests.exceptions.Timeout:
            raise NetworkError(f"Request timed out: {target}")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection failed: {e}")

        section("Response")
        print(color(f"  Status   : ", "dark") +
              color(str(resp.status_code), "green" if resp.status_code < 400 else "red"))
        print(color(f"  Final URL: ", "dark") + color(resp.url, "cyan"))

        section("All Headers")
        for k, v in resp.headers.items():
            print(color(f"  {k:<35}: ", "dark") + color(v, "white"))

        section("Info Disclosure")
        leaked = False
        for h in INFO_LEAKING:
            if h in resp.headers:
                self.medium(f"{h} header exposed", resp.headers[h])
                leaked = True
        if not leaked:
            success("No server info disclosed.")

        section("Security Headers")
        missing = []
        for header, (desc, sev) in SEC_HEADERS.items():
            if header in resp.headers:
                print(color(f"  [✔] {header}", "green"))
            else:
                missing.append((header, desc, sev))
                c = "red" if sev == "critical" else "yellow"
                print(color(f"  [✘] {header}", c) + color(f" — {desc} [{sev}]", "dark"))
                if sev in ("critical", "high"):
                    self.high(f"Missing {header}", desc)
                else:
                    self.medium(f"Missing {header}", desc)

        print()
        if missing:
            warn(f"{len(missing)} security header(s) missing.")
        else:
            success("All key security headers present.")
