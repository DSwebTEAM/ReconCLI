"""engines/analysis/jsrecon.py — Extract endpoints, secrets from JS bundles."""

import re
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url
from core.errors      import NetworkError

# Endpoint patterns
ENDPOINT_RE = re.compile(
    r"""['"` ]((?:/api/|/v\d/|/graphql|/rest/|/endpoint/)[a-zA-Z0-9/_\-{}:?=&.%]+)""",
    re.IGNORECASE
)

# Secret patterns
SECRET_PATTERNS = [
    ("OpenAI Key",      re.compile(r"sk-[A-Za-z0-9]{48}")),
    ("Google API Key",  re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitHub PAT",      re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("AWS Key ID",      re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Slack Token",     re.compile(r"xox[baprs]-[0-9A-Za-z\-]+")),
    ("Firebase URL",    re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("API Key",         re.compile(r"""(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]""")),
    ("Secret",          re.compile(r"""(?i)(?:secret|password|passwd)\s*[=:]\s*['"]([^'"]{8,})['"]""")),
    ("Bearer Token",    re.compile(r"Bearer\s+[A-Za-z0-9\-_.]{20,}")),
    ("JWT",             re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
]


class JSRecon(BaseModule):
    name        = "analysis/jsrecon"
    description = "Extract API endpoints and secrets from JavaScript bundles"

    def __init__(self):
        self.options = {
            "TARGET":  Option(required=True,   description="URL or domain to crawl for JS"),
            "DEPTH":   Option(default="1",     description="JS discovery depth (1=homepage only)", kind="int"),
        }
        super().__init__()

    def _find_js_urls(self, requests, base_url: str) -> list:
        """Find all JS file URLs from a page."""
        try:
            resp = requests.get(base_url, timeout=self._timeout,
                                headers={"User-Agent": "ReconCLI/3.0"})
            body = resp.text
        except Exception:
            return []

        # Find <script src="..."> and explicit .js URLs
        script_re = re.compile(r'<script[^>]+src=[\'"]([^\'"]+\.js[^\'"]*)[\'"]', re.IGNORECASE)
        raw       = script_re.findall(body)

        # Normalize to absolute URLs
        from urllib.parse import urljoin
        return [urljoin(base_url, u) for u in raw]

    def _analyze_js(self, content: str) -> tuple[list, list]:
        """Return (endpoints, secrets) found in JS content."""
        endpoints = list(set(ENDPOINT_RE.findall(content)))
        secrets   = []
        for label, pattern in SECRET_PATTERNS:
            matches = pattern.findall(content)
            for m in matches:
                secrets.append((label, m[:80]))
        return endpoints, secrets

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))
        depth    = int(self.opt("DEPTH"))

        info(f"Discovering JS files on {target}...\n")
        js_urls = self._find_js_urls(requests, target)

        # Common bundle paths if none found
        if not js_urls:
            from urllib.parse import urlparse
            base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
            candidates = [
                f"{base}/static/js/main.js",
                f"{base}/assets/index.js",
                f"{base}/js/app.js",
                f"{base}/bundle.js",
            ]
            for url in candidates:
                try:
                    r = requests.head(url, timeout=4)
                    if r.status_code == 200:
                        js_urls.append(url)
                except Exception:
                    pass

        if not js_urls:
            warn("No JavaScript files found.")
            return

        info(f"Found {len(js_urls)} JS file(s). Analyzing...\n")

        all_endpoints = []
        all_secrets   = []

        for js_url in js_urls:
            try:
                resp = requests.get(js_url, timeout=self._timeout,
                                    headers={"User-Agent": "ReconCLI/3.0"})
                if resp.status_code != 200:
                    continue
                size = len(resp.content)
                print(color(f"  Analyzing: {js_url[:70]}", "dark") +
                      color(f" ({size//1024}kb)", "dark"))
                eps, secs = self._analyze_js(resp.text)
                all_endpoints.extend(eps)
                all_secrets.extend(secs)
            except Exception as e:
                warn(f"Failed to fetch {js_url}: {e}")

        # Deduplicate
        all_endpoints = list(set(all_endpoints))
        all_secrets   = list(set(all_secrets))

        if all_endpoints:
            section(f"API Endpoints Found ({len(all_endpoints)})")
            for ep in sorted(all_endpoints):
                print(color(f"  → {ep}", "cyan"))
                self.note("JS endpoint", ep)

        if all_secrets:
            section(f"Potential Secrets ({len(all_secrets)})")
            for label, val in all_secrets:
                print(color(f"  [{label}] ", "red") + color(val, "yellow"))
                self.critical(f"Secret in JS: {label}", val)

        print()
        if not all_endpoints and not all_secrets:
            success("No endpoints or secrets found in JS bundles.")
        else:
            if all_secrets:
                error(f"{len(all_secrets)} secret(s) found in JS — remove immediately!")
            if all_endpoints:
                info(f"{len(all_endpoints)} endpoint(s) discovered.")
