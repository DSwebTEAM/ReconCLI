"""engines/security/dirbust.py — Directory and file bruteforcer."""

import concurrent.futures
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url
from core.compat      import get_wordlist, get_threads

BUILTIN = [
    "admin","administrator","login","dashboard","panel","cp",
    "api","api/v1","api/v2","graphql","config","configuration",
    ".env",".git",".git/config","backup","backups","db","uploads",
    "upload","files","static","assets","robots.txt","sitemap.xml",
    ".well-known/security.txt","phpinfo.php","console","debug","trace",
    "logs","wp-admin","wp-login.php","wp-config.php","server-status",
    "swagger","swagger-ui","swagger.json","openapi.json","api-docs",
    "metrics","health","healthz","actuator","actuator/health",
    ".htaccess",".htpasswd","crossdomain.xml","package.json",
    "yarn.lock","requirements.txt",
]

STATUS_C = {200:"green", 201:"green", 301:"cyan", 302:"cyan",
            401:"yellow", 403:"yellow", 500:"red"}

CRITICAL_PATHS = [".env",".git","config.json","phpinfo","actuator","dump","backup",".htpasswd"]


class DirBust(BaseModule):
    name        = "security/dirbust"
    description = "Discover hidden paths, admin panels, exposed files"

    def __init__(self):
        self.options = {
            "TARGET":   Option(required=True,   description="URL or domain"),
            "WORDLIST": Option(default="builtin", description="'builtin' or path to file"),
            "THREADS":  Option(default=str(get_threads()), description="Threads", kind="int"),
        }
        super().__init__()

    def _load(self) -> list:
        spec = self.opt("WORDLIST") or "builtin"
        if spec == "builtin":
            wl = get_wordlist("dirs.txt")
            try:
                with open(wl) as f:
                    extra = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                return list(set(BUILTIN + extra))
            except FileNotFoundError:
                return BUILTIN
        try:
            with open(spec) as f:
                return [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            warn(f"Wordlist not found: {spec} — using builtin")
            return BUILTIN

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))
        threads  = int(self.opt("THREADS"))
        words    = self._load()

        session  = requests.Session()
        session.headers["User-Agent"] = "ReconCLI/3.0"

        info(f"Scanning {len(words)} paths  threads={threads}\n")

        found = []

        def check(path):
            url = f"{target.rstrip('/')}/{path}"
            try:
                resp = session.get(url, timeout=self._timeout, allow_redirects=False)
                if resp.status_code not in (404, 400, 410):
                    found.append((url, path, resp.status_code, len(resp.content)))
                    c = STATUS_C.get(resp.status_code, "white")
                    print(color(f"  [{resp.status_code}] ", c) +
                          color(url, "white") +
                          color(f" ({len(resp.content)}b)", "dark"))
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(check, words)

        print()
        success(f"{len(found)} path(s) found.")

        critical = [(url, path, sc) for url, path, sc, _ in found
                    if any(c in path for c in CRITICAL_PATHS) and sc == 200]
        if critical:
            section("Critical Exposures")
            for url, path, sc in critical:
                self.critical(f"Exposed: {path}", url)
