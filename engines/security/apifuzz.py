"""engines/security/apifuzz.py — API endpoint discovery and injection probing."""

import re
import concurrent.futures
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url

API_PATHS = [
    "api/login","api/auth","api/auth/login","api/auth/register","api/auth/token",
    "api/auth/refresh","api/token","api/register","api/logout","api/me","api/user",
    "api/users","api/v1/users","api/v1/admin","api/v1/config","api/v1/settings",
    "api/v2/users","api/health","api/status","api/ping","api/version",
    "api/debug","api/test","api/info","api/admin","api/admin/users",
    "api/keys","api/apikeys","api/tokens","api/upload","api/files",
    "api/search","api/query","api/graphql","api/chat","api/characters",
    "api/sessions","api/messages","api/history",
]

INJECT = {
    "SQLi": ["' OR '1'='1", "1; DROP TABLE users--"],
    "XSS":  ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>'],
    "SSTI": ["{{7*7}}", "${7*7}"],
}

SQL_ERRORS = ["syntax error","mysql","sqlite","postgresql","ora-","sqlstate","unclosed"]


class APIFuzzer(BaseModule):
    name        = "security/apifuzz"
    description = "Discover API endpoints and probe for SQLi, XSS, SSTI"

    def __init__(self):
        self.options = {
            "TARGET":  Option(required=True,   description="URL or domain"),
            "THREADS": Option(default="15",    description="Threads", kind="int"),
            "INJECT":  Option(default="true",  description="Run injection probes", kind="bool"),
        }
        super().__init__()

    def _probe(self, session, base: str, path: str) -> list:
        results = []
        url = f"{base.rstrip('/')}/{path}"
        for method in ["GET", "POST"]:
            try:
                resp = session.request(method, url, json={} if method=="POST" else None,
                                       timeout=self._timeout)
                if resp.status_code not in (404, 410):
                    results.append((method, url, resp.status_code, len(resp.content)))
            except Exception:
                pass
        return results

    def _inject(self, session, url: str) -> list[tuple[str, str]]:
        findings = []
        for vtype, payloads in INJECT.items():
            for p in payloads[:1]:
                try:
                    resp = session.get(url, params={"q": p, "id": p},
                                       timeout=self._timeout)
                    body = resp.text.lower()
                    if vtype == "SQLi" and any(e in body for e in SQL_ERRORS):
                        findings.append((vtype, f"DB error in response — possible SQLi"))
                    if vtype == "XSS" and p.lower() in body:
                        findings.append((vtype, f"Payload reflected — possible XSS"))
                    if vtype == "SSTI" and "49" in body:
                        findings.append((vtype, f"Template evaluated (7*7=49) — SSTI!"))
                except Exception:
                    pass
        return findings

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))
        threads  = int(self.opt("THREADS"))
        do_inject = bool(self.opt("INJECT"))

        session = requests.Session()
        session.headers.update({"User-Agent":"ReconCLI/3.0",
                                 "Content-Type":"application/json",
                                 "Accept":"application/json"})

        info(f"Fuzzing {len(API_PATHS)} API paths  threads={threads}\n")

        found = []

        def check(path):
            results = self._probe(session, target, path)
            for method, url, status, size in results:
                found.append((method, url, status, size))
                c = "green" if status==200 else "yellow" if status in (401,403) else "cyan"
                print(color(f"  [{status}] ", c) +
                      color(f"{method:<6}", "dark") +
                      color(url, "white") +
                      color(f" ({size}b)", "dark"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(check, API_PATHS)

        print()
        success(f"{len(found)} endpoint(s) discovered.")

        ok_urls = [url for _, url, s, _ in found if s == 200]
        if do_inject and ok_urls:
            section("Injection Probes")
            for url in ok_urls[:10]:
                hits = self._inject(session, url)
                if hits:
                    for vtype, msg in hits:
                        self.critical(f"{vtype}: {msg}", url)
                else:
                    print(color(f"  [✔] {url}", "green") + color(" clean", "dark"))

        unauthed_admin = [url for _, url, s, _ in found if s==200 and "admin" in url]
        if unauthed_admin:
            section("Unauthenticated Admin Endpoints")
            for url in unauthed_admin:
                self.critical("Admin endpoint accessible without auth", url)
