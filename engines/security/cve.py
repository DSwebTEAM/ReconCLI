"""engines/security/cve.py — Detect outdated software versions with known CVEs."""

import re
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url
from core.errors      import NetworkError

VULN_DB = [
    # (component, regex, min_safe, cves, severity, note)
    ("jQuery",      r"jquery[/\s]+(\d+\.\d+\.\d+)", "3.5.0",
     ["CVE-2020-11022","CVE-2020-11023","CVE-2019-11358"], "HIGH",
     "XSS in jQuery < 3.5.0"),
    ("Bootstrap",   r"bootstrap[/\s]+(\d+\.\d+\.\d+)", "4.3.1",
     ["CVE-2019-8331","CVE-2018-14041"], "MEDIUM",
     "XSS in Bootstrap < 4.3.1"),
    ("Lodash",      r"lodash[/\s]+(\d+\.\d+\.\d+)", "4.17.21",
     ["CVE-2021-23337","CVE-2020-28500","CVE-2019-10744"], "HIGH",
     "Prototype pollution in Lodash < 4.17.21"),
    ("Axios",       r"axios[/\s]+(\d+\.\d+\.\d+)", "1.6.0",
     ["CVE-2023-45857"], "MEDIUM",
     "CSRF in Axios < 1.6.0"),
    ("Vite",        r"vite[/\s]+(\d+\.\d+\.\d+)", "5.0.0",
     ["CVE-2024-23331"], "MEDIUM",
     "Path traversal in Vite dev server < 5.0"),
    ("React",       r"react[/\s]+(\d+\.\d+\.\d+)", "18.0.0",
     ["CVE-2018-6341"], "LOW",
     "XSS in SSR — use React 18+"),
    ("WordPress",   r"WordPress[/\s]+(\d+\.\d+)", "6.4.0",
     ["CVE-2023-5561"], "HIGH",
     "Multiple CVEs in old WordPress"),
    ("Nginx",       r"nginx[/\s]+(\d+\.\d+\.\d+)", "1.24.0",
     ["CVE-2022-41741"], "HIGH",
     "Memory corruption in old nginx"),
    ("Apache",      r"Apache[/\s]+(\d+\.\d+\.\d+)", "2.4.56",
     ["CVE-2023-25690"], "CRITICAL",
     "Request smuggling in Apache < 2.4.56"),
    ("PHP",         r"PHP[/\s]+(\d+\.\d+\.\d+)", "8.1.0",
     ["CVE-2022-31626"], "CRITICAL",
     "Buffer overflow in PHP < 8.1"),
]

INFO_HEADERS = ["Server","X-Powered-By","X-Generator","X-Runtime","X-AspNet-Version"]
SEV_C = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"cyan","LOW":"dark","OK":"green"}


def _vtuple(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return (0, 0, 0)


class CVEScanner(BaseModule):
    name        = "security/cve"
    description = "Detect outdated libraries with known CVEs via page source scanning"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="URL or domain")}
        super().__init__()

    def _scan(self, text: str, extra_headers: dict) -> list[dict]:
        combined = text + " ".join(f"{k}: {v}" for k, v in extra_headers.items())
        results  = []
        seen     = set()

        for component, pattern, min_safe, cves, severity, note in VULN_DB:
            for version in set(re.findall(pattern, combined, re.IGNORECASE)):
                key = f"{component}:{version}"
                if key in seen:
                    continue
                seen.add(key)
                vuln = _vtuple(version) < _vtuple(min_safe)
                results.append({
                    "component": component,
                    "version":   version,
                    "min_safe":  min_safe,
                    "cves":      cves,
                    "severity":  severity if vuln else "OK",
                    "note":      note,
                    "vuln":      vuln,
                })
        return results

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))

        info("Fetching page source + common JS bundles...\n")

        session = requests.Session()
        session.headers["User-Agent"] = "ReconCLI/3.0"

        # Pages to scan
        from urllib.parse import urlparse
        base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        urls = [target,
                f"{base}/assets/index.js",
                f"{base}/static/js/main.js",
                f"{base}/js/app.js"]

        all_findings: dict[str, dict] = {}

        for url in urls:
            try:
                resp = session.get(url, timeout=self._timeout)
                if resp.status_code != 200:
                    continue
                findings = self._scan(resp.text, dict(resp.headers))
                for f in findings:
                    key = f"{f['component']}:{f['version']}"
                    if key not in all_findings:
                        all_findings[key] = f
                        icon = "✘" if f["vuln"] else "✔"
                        c    = SEV_C[f["severity"]]
                        print(color(f"  [{icon}] {f['component']:<16} v{f['version']:<12}", c) +
                              color(f"(safe: v{f['min_safe']}+)", "dark"))
            except Exception:
                pass

        # Header info disclosure
        try:
            resp = session.get(target, timeout=self._timeout)
            section("Server Headers")
            for h in INFO_HEADERS:
                if h in resp.headers:
                    val = resp.headers[h]
                    print(color(f"  {h}: ", "dark") + color(val, "yellow"))
                    self.medium(f"{h} exposed — version fingerprinting risk", val)
        except Exception:
            pass

        # Summary
        vulns = [f for f in all_findings.values() if f["vuln"]]
        section("Summary")

        if not vulns:
            if all_findings:
                success("All detected components appear up to date.")
            else:
                success("No version strings found — version info is well hidden.")
            return

        for f in sorted(vulns, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["severity"])):
            c = SEV_C[f["severity"]]
            print(color(f"\n  [{f['severity']}] {f['component']} v{f['version']}", c))
            print(color(f"  → {f['note']}", "dark"))
            print(color(f"  → CVEs: {', '.join(f['cves'])}", "yellow"))
            print(color(f"  → Upgrade to v{f['min_safe']}+", "cyan"))
            self.finding(f["severity"], f"{f['component']} v{f['version']} — {f['note']}",
                         ", ".join(f["cves"]))

        print()
        error(f"{len(vulns)} vulnerable component(s). Upgrade immediately.")
