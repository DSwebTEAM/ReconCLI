"""engines/security/cors.py — CORS misconfiguration detector."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_url
from core.errors      import NetworkError

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "http://localhost",
    "https://127.0.0.1",
]


class CORSCheck(BaseModule):
    name        = "security/cors"
    description = "Detect CORS misconfigurations — origin reflection, wildcard + credentials"

    def __init__(self):
        self.options = {"TARGET": Option(required=True, description="URL or domain")}
        super().__init__()

    def _test(self, session, url: str, origin: str) -> tuple[str, str, str]:
        try:
            resp = session.options(url, timeout=self._timeout, headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            })
            return (
                resp.headers.get("Access-Control-Allow-Origin", ""),
                resp.headers.get("Access-Control-Allow-Credentials", "false").lower(),
                resp.headers.get("Access-Control-Allow-Methods", ""),
            )
        except Exception:
            return "", "false", ""

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))
        session  = requests.Session()
        session.headers["User-Agent"] = "ReconCLI/3.0"

        info(f"Testing {len(TEST_ORIGINS)} origins against {target}\n")

        for origin in TEST_ORIGINS:
            acao, acac, acam = self._test(session, target, origin)
            if not acao:
                print(color(f"  [-] {origin:<42}", "dark") + color("no CORS header", "dark"))
                continue

            print(color(f"  [?] {origin:<42}", "cyan") + color(f"ACAO={acao}", "white"))

            if acao == "*" and acac == "true":
                self.critical("Wildcard ACAO with credentials=true", f"Origin: {origin}")
            elif acao == origin and acac == "true":
                self.critical("Origin reflected with credentials=true — full CORS bypass possible", origin)
            elif acao == origin and any(x in origin for x in ["evil", "attacker"]):
                self.high("Reflects attacker origin", f"ACAO={acao}")
            elif acao == "null":
                self.high("Accepts null origin — exploitable via sandboxed iframe")
            elif acao == "*":
                self.medium("Wildcard ACAO — all origins allowed")

        print()
        info("Fix: Set Access-Control-Allow-Origin to your exact domain, never *+credentials.")
