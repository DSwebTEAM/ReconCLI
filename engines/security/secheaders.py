"""engines/security/secheaders.py — Deep security headers audit with grading."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url
from core.errors      import NetworkError

SPEC = [
    {
        "name":     "Strict-Transport-Security",
        "severity": "CRITICAL",
        "desc":     "Forces HTTPS — protects against protocol downgrade attacks.",
        "good":     lambda v: "max-age" in v and
                    int(v.split("max-age=")[1].split(";")[0].strip()) >= 31536000,
        "fix":      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "name":     "Content-Security-Policy",
        "severity": "CRITICAL",
        "desc":     "Prevents XSS and injection. Controls which resources can load.",
        "good":     lambda v: "default-src" in v or "script-src" in v,
        "fix":      "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
    },
    {
        "name":     "X-Frame-Options",
        "severity": "HIGH",
        "desc":     "Prevents clickjacking via iframe embedding.",
        "good":     lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "fix":      "X-Frame-Options: DENY",
    },
    {
        "name":     "X-Content-Type-Options",
        "severity": "MEDIUM",
        "desc":     "Prevents MIME type sniffing.",
        "good":     lambda v: v.lower() == "nosniff",
        "fix":      "X-Content-Type-Options: nosniff",
    },
    {
        "name":     "Referrer-Policy",
        "severity": "MEDIUM",
        "desc":     "Controls referrer info sent to other sites.",
        "good":     lambda v: v in ("no-referrer", "strict-origin",
                                    "strict-origin-when-cross-origin"),
        "fix":      "Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "name":     "Permissions-Policy",
        "severity": "LOW",
        "desc":     "Restricts browser APIs (camera, mic, geolocation).",
        "good":     lambda v: len(v) > 0,
        "fix":      "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
]

SEV_C = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dark"}


class SecHeaders(BaseModule):
    name        = "security/secheaders"
    description = "Deep security headers audit with letter grade scoring"

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
        score   = 0
        issues  = []

        section("Header Analysis")
        for spec in SPEC:
            name = spec["name"]
            val  = headers.get(name.lower())
            sev  = spec["severity"]

            if val is None:
                issues.append(spec)
                print(color(f"  [✘] {name}", SEV_C[sev]) +
                      color(f" — MISSING [{sev}]", "dark"))
                self._log_issue(spec)
            else:
                try:
                    good = spec["good"](val)
                except Exception:
                    good = True

                if good:
                    score += 1
                    print(color(f"  [✔] {name}", "green") +
                          color(f" = {val[:55]}", "dark"))
                else:
                    issues.append(spec)
                    print(color(f"  [~] {name}", "yellow") +
                          color(f" = {val[:40]}  [WEAK CONFIG]", "dark"))
                    self._log_issue(spec)

        pct   = int((score / len(SPEC)) * 100)
        grade = "A+" if pct==100 else "A" if pct>=85 else "B" if pct>=70 else "C" if pct>=50 else "F"
        gc    = "green" if grade in ("A+","A") else "yellow" if grade=="B" else "red"

        section("Score")
        print(color(f"  {score}/{len(SPEC)} ({pct}%)  Grade: ", "dark") + color(grade, gc))

        if issues:
            section("Fixes")
            for spec in issues:
                print(color(f"\n  [{spec['severity']}] {spec['name']}", SEV_C[spec['severity']]))
                print(color(f"  → {spec['desc']}", "dark"))
                print(color(f"  → {spec['fix']}", "cyan"))

        print()
        if pct == 100:
            success("Perfect security headers!")
        elif pct >= 70:
            warn(f"{len(issues)} header(s) need attention.")
        else:
            error(f"Poor security posture — {len(issues)} issue(s) found.")

    def _log_issue(self, spec):
        sev = spec["severity"]
        if sev == "CRITICAL":
            self.critical(f"Missing {spec['name']}", spec["desc"])
        elif sev == "HIGH":
            self.high(f"Missing {spec['name']}", spec["desc"])
        elif sev == "MEDIUM":
            self.medium(f"Missing {spec['name']}", spec["desc"])
        else:
            self.low(f"Missing {spec['name']}", spec["desc"])
