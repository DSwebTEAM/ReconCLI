"""engines/security/csrf.py — CSRF protection validator."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url
from core.errors      import NetworkError

STATE_PATHS = [
    "api/login","api/register","api/user/update","api/password",
    "api/settings","api/profile","api/chat","login","register",
]


class CSRFValidator(BaseModule):
    name        = "security/csrf"
    description = "Test state-changing endpoints for CSRF protections"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="URL or domain")}
        super().__init__()

    def _check(self, session, url: str) -> tuple[bool, str]:
        """Returns (vulnerable, protection_method)."""
        try:
            get_resp  = session.get(url, timeout=self._timeout)
            if get_resp.status_code in (404, 410):
                return False, "not found"

            # Check SameSite
            cookie_hdr = get_resp.headers.get("Set-Cookie","").lower()
            if "samesite=strict" in cookie_hdr:
                return False, "SameSite=Strict"
            if "samesite=lax" in cookie_hdr:
                return False, "SameSite=Lax"

            # CSRF token in body
            body_lower = get_resp.text.lower()
            if any(t in body_lower for t in ["csrf","xsrf","_token","csrfmiddlewaretoken"]):
                return False, "CSRF token in response"

            # Cross-origin POST
            post_resp = session.post(url, json={"csrf_test": True},
                                     timeout=self._timeout,
                                     headers={"Origin": "https://evil.com",
                                              "Referer": "https://evil.com/"})
            if post_resp.status_code not in (401, 403, 404, 405, 422):
                return True, f"HTTP {post_resp.status_code}"
            return False, f"Blocked ({post_resp.status_code})"

        except Exception:
            return False, "error"

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))
        session  = requests.Session()
        session.headers.update({"User-Agent": "ReconCLI/3.0",
                                 "Content-Type": "application/json"})

        info(f"Testing {len(STATE_PATHS)} state-changing endpoints...\n")
        vulnerable = []

        for path in STATE_PATHS:
            url  = f"{target.rstrip('/')}/{path}"
            vuln, method = self._check(session, url)
            label = color(f"  {path:<40}", "cyan")
            if vuln:
                vulnerable.append((path, url, method))
                print(label + color(f"[✘] VULNERABLE — {method}", "red"))
            else:
                print(label + color(f"[✔] {method}", "green"))

        print()
        if vulnerable:
            for path, url, method in vulnerable:
                self.high(f"CSRF vulnerable endpoint: {path}", method)
            section("Fix")
            print(color("  1. Set SameSite=Lax or Strict on session cookies", "white"))
            print(color("  2. Validate Origin/Referer on state-changing routes", "white"))
            print(color("  3. Use CSRF tokens (csurf for Express)", "white"))
        else:
            success("All endpoints appear CSRF-protected.")
