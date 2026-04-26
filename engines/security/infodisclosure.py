"""engines/security/infodisclosure.py — Scan for exposed secrets, configs, stack traces."""

import re
import concurrent.futures
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url
from core.errors      import NetworkError

SENSITIVE_PATHS = [
    ".env",".env.local",".env.production",".env.development",".env.backup",
    "config.js","config.json","config.yaml","config.yml","app.config.js",
    "vite.config.js","next.config.js","settings.py",
    "secrets.json","credentials.json",".aws/credentials",
    "firebase.json",".firebaserc",
    ".git/config",".git/HEAD",".gitignore",
    "package.json","package-lock.json","yarn.lock","requirements.txt",
    "webpack-stats.json","build/asset-manifest.json",
    "error.log","access.log","debug.log","logs/error.log",
    "backup.sql","database.sql","dump.sql","backup.zip",
    "phpinfo.php","server-status","actuator/env","actuator/beans",
    "swagger.json","openapi.json","api-docs",
    ".htaccess",".htpasswd","web.config","crossdomain.xml",
]

SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})"), "API Key"),
    (re.compile(r"(?i)(secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})"),       "Secret"),
    (re.compile(r"(?i)(password)\s*[=:]\s*['\"]?([^\s'\"]{6,})"),             "Password"),
    (re.compile(r"sk-[A-Za-z0-9]{48}"),                                        "OpenAI Key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                                    "Google API Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),                                       "GitHub PAT"),
]

STACK_PATTERNS = [
    r"Traceback \(most recent call",
    r"SyntaxError:|TypeError:|ReferenceError:",
    r"Fatal error:",r"SQLSTATE\[",r"Stack trace:",r"at \w+\.\w+\(",
]


class InfoDisclosure(BaseModule):
    name        = "security/infodisclosure"
    description = "Scan for exposed .env, .git, secrets, stack traces, config files"

    def __init__(self):
        self.options = {
            "TARGET":  Option(required=True, description="URL or domain"),
            "THREADS": Option(default="20",  description="Concurrent threads", kind="int"),
        }
        super().__init__()

    def _check(self, session, base: str, path: str) -> tuple[str, int, str]:
        url = f"{base.rstrip('/')}/{path}"
        try:
            resp = session.get(url, timeout=self._timeout)
            if resp.status_code == 200:
                return url, 200, resp.text[:3000]
        except Exception:
            pass
        return url, 0, ""

    def _scan_content(self, content: str) -> list[tuple[str, str]]:
        findings = []
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(content):
                findings.append(("SECRET", label))
        for p in STACK_PATTERNS:
            if re.search(p, content):
                findings.append(("STACK_TRACE", "Stack trace / error leak"))
                break
        return findings

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))
        threads  = int(self.opt("THREADS"))
        session  = requests.Session()
        session.headers["User-Agent"] = "ReconCLI/3.0"

        info(f"Scanning {len(SENSITIVE_PATHS)} paths  threads={threads}\n")

        exposed = []

        def check(path):
            url, status, content = self._check(session, target, path)
            if status == 200:
                content_findings = self._scan_content(content)
                exposed.append((url, path, content_findings))
                badge = color("  [200] ", "red")
                print(badge + color(url, "white"))
                for ftype, label in content_findings:
                    if ftype == "SECRET":
                        error(f"       🔑 {label} detected in response!")
                    else:
                        warn(f"       ⚠  {label}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(check, SENSITIVE_PATHS)

        print()
        if not exposed:
            success("No sensitive files exposed.")
            return

        warn(f"{len(exposed)} file(s) publicly accessible.")

        for url, path, findings in exposed:
            for ftype, label in findings:
                if ftype == "SECRET":
                    self.critical(f"Secret exposed: {label}", url)
                else:
                    self.high("Stack trace / error leak", url)
            if not findings:
                self.medium(f"Sensitive file accessible", url)

        section("Immediate Actions")
        for url, path, _ in exposed:
            if ".env" in path or ".git" in path:
                error(f"Block: {path}  (add to Netlify _headers or .htaccess)")
            elif "config" in path.lower():
                warn(f"Review and restrict: {path}")
