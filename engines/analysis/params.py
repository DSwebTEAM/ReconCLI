"""engines/analysis/params.py — Collect URL parameters from crawled pages."""

import re
from urllib.parse import urlparse, parse_qs, urljoin
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_url
from core.errors      import NetworkError


class ParamMiner(BaseModule):
    name        = "analysis/params"
    description = "Collect all URL parameters from crawled pages"

    def __init__(self):
        self.options = {
            "TARGET": Option(required=True, description="URL to crawl"),
            "DEPTH":  Option(default="2",  description="Crawl depth", kind="int"),
        }
        super().__init__()

    def _crawl(self, requests, base: str, depth: int) -> set:
        """Simple crawler, returns all URLs found."""
        visited = set()
        queue   = {base}
        base_host = urlparse(base).netloc

        for _ in range(depth):
            next_q = set()
            for url in queue:
                if url in visited:
                    continue
                visited.add(url)
                try:
                    resp = requests.get(url, timeout=self._timeout,
                                        headers={"User-Agent": "ReconCLI/3.0"})
                    # Find all hrefs
                    links = re.findall(r'href=[\'"]([^\'"#]+)[\'"]', resp.text)
                    for link in links:
                        abs_link = urljoin(url, link)
                        if urlparse(abs_link).netloc == base_host:
                            next_q.add(abs_link)
                except Exception:
                    pass
            queue = next_q - visited

        return visited

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))
        depth    = int(self.opt("DEPTH"))

        info(f"Crawling {target}  depth={depth}...\n")
        urls = self._crawl(requests, target, depth)
        info(f"Crawled {len(urls)} page(s). Extracting parameters...\n")

        all_params: dict[str, set] = {}
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for k, vals in params.items():
                all_params.setdefault(k, set()).update(vals)

        if not all_params:
            warn("No URL parameters found.")
            return

        section(f"Parameters Found ({len(all_params)})")
        for param, vals in sorted(all_params.items()):
            sample = list(vals)[0][:40] if vals else ""
            print(color(f"  {param:<30}", "cyan") + color(f"  e.g. {sample}", "dark"))
            self.note("URL parameter", param)

        # Flag interesting params
        interesting = ["id", "user", "token", "key", "secret", "password",
                       "redirect", "url", "file", "path", "cmd", "exec", "query"]
        flagged = [p for p in all_params if any(i in p.lower() for i in interesting)]
        if flagged:
            section("High-Interest Parameters (injection candidates)")
            for p in flagged:
                self.high(f"Interesting param: {p}", "Test for SQLi, IDOR, open redirect")
                print(color(f"  → {p}", "yellow"))

        print()
        success(f"{len(all_params)} parameter(s) found.")
