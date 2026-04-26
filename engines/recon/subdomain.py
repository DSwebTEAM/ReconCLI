"""engines/recon/subdomain.py — Wordlist-based subdomain discovery."""

import socket
import concurrent.futures
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_host
from core.compat      import get_wordlist, get_threads

BUILTIN = [
    "www","mail","ftp","admin","api","dev","staging","test","app",
    "blog","shop","portal","cdn","static","media","m","mobile","beta",
    "dashboard","secure","vpn","jenkins","gitlab","git","ci","status",
    "monitor","db","mysql","redis","mongo","smtp","ns1","ns2",
    "cpanel","phpmyadmin","adminer","grafana","api-dev","api-staging",
    "internal","docs","wiki","auth","sso","id","accounts","billing",
]

RISKY_KEYWORDS = [
    "admin","dev","staging","test","jenkins","gitlab",
    "phpmyadmin","adminer","db","redis","mongo","internal","vpn",
]


class SubdomainEnum(BaseModule):
    name        = "recon/subdomain"
    description = "Wordlist-based subdomain discovery with risk flagging"

    def __init__(self):
        self.options = {
            "TARGET":   Option(required=True, description="Base domain  e.g. hibiki.app"),
            "WORDLIST": Option(default="builtin", description="'builtin' or path to wordlist file"),
            "THREADS":  Option(default=str(get_threads()), description="Concurrent threads", kind="int"),
        }
        super().__init__()

    def _load_wordlist(self) -> list:
        spec = self.opt("WORDLIST") or "builtin"
        if spec == "builtin":
            # Try loading the bundled wordlist too
            wl_path = get_wordlist("subdomains.txt")
            extra   = []
            try:
                with open(wl_path) as f:
                    extra = [l.strip() for l in f if l.strip()]
            except FileNotFoundError:
                pass
            return list(set(BUILTIN + extra))
        try:
            with open(spec) as f:
                return [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            warn(f"Wordlist not found: {spec} — using builtin")
            return BUILTIN

    def _resolve(self, domain: str, sub: str) -> tuple[str, str] | tuple[None, None]:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return fqdn, ip
        except Exception:
            return None, None

    def run(self):
        target  = require_host(self.opt("TARGET"))
        threads = int(self.opt("THREADS"))
        words   = self._load_wordlist()

        info(f"Enumerating {len(words)} subdomains on {target}  threads={threads}\n")

        found = []

        def check(sub):
            fqdn, ip = self._resolve(target, sub)
            if fqdn:
                found.append((fqdn, ip))
                print(color(f"  [+] {fqdn:<42}", "green") + color(f"→ {ip}", "cyan"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(check, words)

        print()
        if not found:
            warn("No subdomains discovered.")
            return

        success(f"{len(found)} subdomain(s) found.")
        for fqdn, ip in found:
            self.note(f"Subdomain: {fqdn}", ip)

        risky = [(f, ip) for f, ip in found
                 if any(k in f for k in RISKY_KEYWORDS)]
        if risky:
            section("Exposed Sensitive Subdomains")
            for fqdn, ip in risky:
                self.high(f"Sensitive subdomain exposed: {fqdn}", ip)
