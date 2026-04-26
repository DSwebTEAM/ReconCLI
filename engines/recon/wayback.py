"""engines/recon/wayback.py — Discover historical URLs from Wayback Machine."""

from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_host
from core.errors      import NetworkError


INTERESTING_EXTS = [
    ".json", ".xml", ".yaml", ".yml", ".env", ".config",
    ".sql", ".bak", ".backup", ".log", ".txt", ".php",
    ".asp", ".aspx", ".jsp",
]

INTERESTING_PATHS = [
    "admin", "login", "api", "config", "backup",
    "debug", "test", "dev", "staging", "internal",
    ".git", ".env", "wp-admin",
]


class Wayback(BaseModule):
    name        = "recon/wayback"
    description = "Find historical URLs from Wayback Machine / Common Crawl"

    def __init__(self):
        self.options = {
            "TARGET": Option(required=True,  description="Domain  e.g. hibiki.app"),
            "LIMIT":  Option(default="200",  description="Max URLs to fetch", kind="int"),
        }
        super().__init__()

    def run(self):
        requests = self.need_package("requests")
        target   = require_host(self.opt("TARGET"))
        limit    = int(self.opt("LIMIT"))

        info(f"Querying Wayback Machine for {target}  limit={limit}...\n")

        try:
            resp = requests.get(
                "http://web.archive.org/cdx/search/cdx",
                params={
                    "url":        f"*.{target}/*",
                    "output":     "json",
                    "fl":         "original",
                    "collapse":   "urlkey",
                    "limit":      limit,
                    "filter":     "statuscode:200",
                },
                timeout=15,
                headers={"User-Agent": "ReconCLI/3.0"}
            )
            data = resp.json()
        except Exception as e:
            raise NetworkError(f"Wayback API failed: {e}")

        if not data or len(data) <= 1:
            warn("No historical URLs found.")
            return

        urls = [row[0] for row in data[1:]]  # skip header row
        info(f"Found {len(urls)} historical URL(s)\n")

        # Categorize
        interesting = []
        normal      = []
        for url in urls:
            url_lower = url.lower()
            if (any(url_lower.endswith(ext) for ext in INTERESTING_EXTS) or
                    any(f"/{p}" in url_lower for p in INTERESTING_PATHS)):
                interesting.append(url)
            else:
                normal.append(url)

        if interesting:
            section(f"Interesting URLs ({len(interesting)})")
            for url in interesting[:50]:
                print(color(f"  → {url}", "yellow"))
                self.high("Interesting historical URL", url)

        if normal:
            section(f"All Other URLs (showing first 30 of {len(normal)})")
            for url in normal[:30]:
                print(color(f"  → {url}", "dark"))
                self.note("Historical URL", url)

        print()
        success(f"{len(urls)} total URLs found. {len(interesting)} flagged as interesting.")
