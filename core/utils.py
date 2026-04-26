"""
core/utils.py — Shared output helpers for ReconCLI v3
Fixed: Windows colors, section overflow, path issues.
"""

import sys
import os
from datetime import datetime
from core.compat import init_colors, IS_WIN, get_output_dir

# Init colors on import (no-op on Linux/Mac)
init_colors()

# ── ANSI color map ────────────────────────────────────────────────────────────

_COLORS = {
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
    "white":  "\033[97m",
    "dark":   "\033[90m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def _supports_color() -> bool:
    """True if the terminal supports ANSI colors."""
    if IS_WIN:
        # colorama handles this on Windows after init
        try:
            import colorama  # noqa
            return True
        except ImportError:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_COLOR_OK = _supports_color()

def color(text: str, c: str = "white") -> str:
    if not _COLOR_OK:
        return str(text)
    return f"{_COLORS.get(c, '')}{text}{_COLORS['reset']}"


# ── Print helpers ─────────────────────────────────────────────────────────────

def success(msg: str): print(color(f"  [✔] {msg}", "green"))
def info(msg: str):    print(color(f"  [*] {msg}", "cyan"))
def warn(msg: str):    print(color(f"  [!] {msg}", "yellow"))
def error(msg: str):   print(color(f"  [✘] {msg}", "red"))

def section(msg: str):
    """Print a section divider. Safe for any message length."""
    pad = max(0, 42 - len(msg))
    print(color(f"\n  ── {msg} " + "─" * pad, "dark"))

def print_result_header(module: str, target: str):
    """Standardised header printed at the start of every module run."""
    print(color(f"\n  {'═' * 56}", "dark"))
    print(color("  MODULE  : ", "dark") + color(module.upper(), "cyan"))
    print(color("  TARGET  : ", "dark") + color(target, "white"))
    print(color("  TIME    : ", "dark") + color(timestamp(), "dark"))
    print(color(f"  {'═' * 56}\n", "dark"))

def divider(width: int = 56):
    print(color("  " + "─" * width, "dark"))


# ── Error display (from typed exceptions) ─────────────────────────────────────

def print_error(exc) -> None:
    """Pretty-print a ReconCLIError with its hint."""
    from core.errors import ReconCLIError
    if isinstance(exc, ReconCLIError):
        error(exc.message)
        if exc.hint:
            print(color(f"      → {exc.hint}", "dark"))
    else:
        error(str(exc))


# ── Time ──────────────────────────────────────────────────────────────────────

def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def datestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ── Output / save ─────────────────────────────────────────────────────────────

def save_output(filename: str, content: str) -> str:
    """Save content to output dir. Returns absolute path."""
    out_dir = get_output_dir()
    path    = os.path.join(out_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    success(f"Saved → {path}")
    return path


# ── Dependency lazy-import helper ─────────────────────────────────────────────

def require_package(import_name: str, pip_name: str = None):
    """
    Lazily import a package. Raises DependencyError with install hint if missing.
    Usage:
        requests = require_package("requests")
        dns      = require_package("dns.resolver", "dnspython")
    """
    from core.errors import DependencyError
    from core.compat import pip_hint
    import importlib
    pip_name = pip_name or import_name
    try:
        return importlib.import_module(import_name)
    except ImportError:
        raise DependencyError(pip_name, pip_hint(pip_name))


def require_bin(binary: str):
    """
    Check a binary exists on PATH. Raises DependencyError with hint if not.
    Usage:
        require_bin("traceroute")
    """
    from core.errors import DependencyError
    from core.compat import find_bin, bin_install_hint
    if not find_bin(binary):
        raise DependencyError(binary, bin_install_hint(binary))
