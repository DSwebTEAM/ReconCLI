"""
core/validator.py — Target validation for ReconCLI v3
All validation happens here before a module ever runs.
"""

import re
import socket
import ipaddress
from core.errors import TargetError, DNSError


# ── Regexes ───────────────────────────────────────────────────────────────────

_RE_HOSTNAME = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)


# ── Core validators ───────────────────────────────────────────────────────────

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False

def is_hostname(value: str) -> bool:
    return bool(_RE_HOSTNAME.match(value))

def is_url(value: str) -> bool:
    return bool(_RE_URL.match(value))


# ── Normalizers ───────────────────────────────────────────────────────────────

def normalize_url(target: str) -> str:
    """Ensure target has https:// prefix."""
    target = target.strip()
    if not _RE_URL.match(target):
        return "https://" + target
    return target

def extract_host(target: str) -> str:
    """Extract bare hostname/IP from URL or return as-is."""
    target = target.strip()
    if _RE_URL.match(target):
        match = re.match(r"https?://([^/:]+)", target)
        return match.group(1) if match else target
    return target

def strip_path(target: str) -> str:
    """Remove path from URL, keep scheme + host."""
    target = normalize_url(target)
    match  = re.match(r"(https?://[^/]+)", target)
    return match.group(1) if match else target


# ── Resolution ────────────────────────────────────────────────────────────────

def resolve(target: str) -> str:
    """
    Resolve hostname to IP. Returns IP string.
    Raises DNSError on failure.
    """
    host = extract_host(target)
    if is_ip(host):
        return host
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise DNSError(host)


# ── Typed validators (raise TargetError) ──────────────────────────────────────

def require_url(target: str) -> str:
    """Validate and normalize a URL target. Returns normalized URL."""
    target = target.strip()
    if not target:
        raise TargetError(target, "target is empty", "https://example.com")
    normalized = normalize_url(target)
    host = extract_host(normalized)
    if not (is_ip(host) or is_hostname(host)):
        raise TargetError(target, "not a valid hostname or IP", "https://example.com or 192.168.1.1")
    return normalized

def require_host(target: str) -> str:
    """Validate a hostname or IP (no URL needed). Returns bare host."""
    target = target.strip()
    if not target:
        raise TargetError(target, "target is empty", "example.com or 192.168.1.1")
    host = extract_host(target)
    if not (is_ip(host) or is_hostname(host)):
        raise TargetError(target, "not a valid hostname or IP", "example.com or 192.168.1.1")
    return host

def require_ip(target: str) -> str:
    """Validate a plain IP address."""
    target = target.strip()
    if not is_ip(target):
        raise TargetError(target, "not a valid IP address", "192.168.1.1")
    return target

def require_cidr(target: str) -> str:
    """Validate a CIDR range."""
    target = target.strip()
    if not is_cidr(target):
        raise TargetError(target, "not a valid CIDR range", "192.168.1.0/24")
    return target

def require_host_or_cidr(target: str) -> str:
    """Accept either a hostname/IP or a CIDR range."""
    target = target.strip()
    if is_cidr(target) or is_ip(target) or is_hostname(target):
        return target
    # Try extracting host from URL
    host = extract_host(target)
    if is_ip(host) or is_hostname(host):
        return host
    raise TargetError(target, "not a valid IP, hostname, or CIDR range",
                      "192.168.1.1  or  192.168.1.0/24  or  example.com")
