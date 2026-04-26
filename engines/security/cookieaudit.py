"""engines/security/cookieaudit.py — Session and cookie security audit."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url
from core.errors      import NetworkError


class CookieAudit(BaseModule):
    name        = "security/cookieaudit"
    description = "Audit session cookies for HttpOnly, Secure, SameSite flags"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="URL or domain")}
        super().__init__()

    def _parse_cookies(self, resp) -> list[dict]:
        raw = []
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                raw.append(v)

        cookies = []
        for cs in raw:
            parts  = [p.strip() for p in cs.split(";")]
            nv     = parts[0].split("=", 1)
            name   = nv[0].strip()
            value  = nv[1].strip() if len(nv) > 1 else ""
            flags  = {}
            for p in parts[1:]:
                kv = p.split("=", 1)
                flags[kv[0].strip().lower()] = kv[1].strip() if len(kv) > 1 else True
            cookies.append({"name": name, "value": value, "flags": flags})
        return cookies

    def _audit(self, cookie: dict) -> list[tuple[str, str]]:
        issues = []
        flags  = cookie["flags"]
        name   = cookie["name"]
        value  = cookie["value"]

        if "httponly" not in flags:
            issues.append(("HIGH",   "Missing HttpOnly — JS can read this cookie (XSS risk)"))
        if "secure" not in flags:
            issues.append(("HIGH",   "Missing Secure flag — sent over HTTP too"))

        ss = flags.get("samesite", "").lower()
        if not ss:
            issues.append(("MEDIUM", "No SameSite — CSRF risk"))
        elif ss == "none" and "secure" not in flags:
            issues.append(("HIGH",   "SameSite=None without Secure — browsers reject this"))

        # Session ID checks
        if any(k in name.lower() for k in ["session","sess","sid","auth","token"]):
            if len(value) < 16:
                issues.append(("HIGH", f"Short session value ({len(value)} chars) — may be predictable"))
            if value.isdigit():
                issues.append(("CRITICAL", "Numeric-only session ID — highly predictable!"))

        return issues

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))

        try:
            resp = requests.get(target, timeout=self._timeout,
                                headers={"User-Agent": "ReconCLI/3.0"},
                                allow_redirects=True)
        except Exception as e:
            raise NetworkError(str(e))

        cookies = self._parse_cookies(resp)
        if not cookies:
            warn("No Set-Cookie headers found on this page.")
            info("Try targeting a login or dashboard endpoint.")
            return

        info(f"Found {len(cookies)} cookie(s)\n")
        all_issues = []

        for ck in cookies:
            section(f"Cookie: {ck['name']}")
            val_preview = ck["value"][:20] + "..." if len(ck["value"]) > 20 else ck["value"]
            print(color(f"  Value : ", "dark") + color(val_preview or "(empty)", "dark"))
            print(color(f"  Flags : ", "dark") + color(str(ck["flags"]), "dark"))

            issues = self._audit(ck)
            if not issues:
                success("All security flags set correctly.")
            else:
                for sev, msg in issues:
                    all_issues.append((ck["name"], sev, msg))
                    c = "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "cyan"
                    print(color(f"  [{sev}] {msg}", c))
                    getattr(self, sev.lower(), self.medium)(msg, f"Cookie: {ck['name']}")

        section("Recommended Cookie")
        print(color("  Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/", "cyan"))

        print()
        if not all_issues:
            success("All cookies have correct security flags.")
        else:
            warn(f"{len(all_issues)} issue(s) across {len(cookies)} cookie(s).")
