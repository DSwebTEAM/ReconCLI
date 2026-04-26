"""
core/compat.py — OS compatibility layer for ReconCLI v3
All platform-specific logic lives here. Every module imports from this.
"""

import sys
import os
import shutil
import platform
import subprocess

# ── Platform detection ────────────────────────────────────────────────────────

SYSTEM   = platform.system().lower()   # 'windows', 'linux', 'darwin'
IS_WIN   = SYSTEM == "windows"
IS_MAC   = SYSTEM == "darwin"
IS_LINUX = SYSTEM == "linux"
IS_TERMUX = os.path.isdir("/data/data/com.termux")

def platform_name() -> str:
    if IS_TERMUX: return "Termux"
    if IS_WIN:    return "Windows"
    if IS_MAC:    return "macOS"
    return "Linux"


# ── Color init ────────────────────────────────────────────────────────────────

def init_colors():
    """Initialize colorama on Windows, no-op elsewhere."""
    if IS_WIN:
        try:
            import colorama
            colorama.init(autoreset=True)
        except ImportError:
            pass  # will still work, just no colors on old Windows


# ── Network helpers ───────────────────────────────────────────────────────────

def ping_cmd(host: str) -> list:
    """Return the correct ping command for this OS."""
    if IS_WIN:
        return ["ping", "-n", "1", "-w", "1000", host]
    else:
        return ["ping", "-c", "1", "-W", "1", host]

def trace_cmd(host: str) -> list:
    """Return the correct traceroute command for this OS."""
    if IS_WIN:
        return ["tracert", "-h", "20", host]
    return ["traceroute", "-m", "20", host]

def get_timeout() -> float:
    """Return appropriate socket/request timeout for this environment."""
    if IS_TERMUX:
        return 6.0   # mobile networks — slightly longer but not too slow
    if IS_WIN:
        return 8.0
    return 5.0

def get_threads() -> int:
    """Return safe thread count for this environment."""
    if IS_TERMUX:
        return 25    # limited RAM on Android
    return 50


# ── Binary detection ──────────────────────────────────────────────────────────

def find_bin(name: str) -> str | None:
    """Cross-platform binary finder. Returns path or None."""
    return shutil.which(name)

def has_bin(name: str) -> bool:
    return find_bin(name) is not None


# ── Install hints ─────────────────────────────────────────────────────────────

def pip_hint(package: str) -> str:
    """Return the correct pip install command for this OS/env."""
    if IS_TERMUX:
        return f"pip install {package} --break-system-packages"
    if IS_WIN:
        return f"pip install {package}"
    return f"pip3 install {package}"

def bin_install_hint(binary: str) -> str:
    """Return OS-specific install hint for a missing binary."""
    hints = {
        "traceroute": {
            "linux":   "sudo apt install traceroute",
            "darwin":  "brew install traceroute",
            "termux":  "pkg install traceroute",
            "windows": "Built-in as 'tracert' — no install needed",
        },
        "nmap": {
            "linux":   "sudo apt install nmap",
            "darwin":  "brew install nmap",
            "termux":  "pkg install nmap",
            "windows": "Download from https://nmap.org/download.html",
        },
        "node": {
            "linux":   "sudo apt install nodejs  OR  https://nodejs.org",
            "darwin":  "brew install node  OR  https://nodejs.org",
            "termux":  "pkg install nodejs",
            "windows": "Download from https://nodejs.org",
        },
        "git": {
            "linux":   "sudo apt install git",
            "darwin":  "brew install git",
            "termux":  "pkg install git",
            "windows": "Download from https://git-scm.com",
        },
    }
    env = "termux" if IS_TERMUX else SYSTEM
    return hints.get(binary, {}).get(env, f"Install {binary} for your OS")


# ── Paths ─────────────────────────────────────────────────────────────────────

def get_base_dir() -> str:
    """Absolute path to ReconCLI root, works installed or as script."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_sessions_dir() -> str:
    d = os.path.join(get_base_dir(), "sessions")
    os.makedirs(d, exist_ok=True)
    return d

def get_wordlist(name: str) -> str:
    return os.path.join(get_base_dir(), "data", "wordlists", name)

def get_output_dir() -> str:
    d = os.path.join(get_base_dir(), "output")
    os.makedirs(d, exist_ok=True)
    return d

def clear_screen():
    os.system("cls" if IS_WIN else "clear")


# ── Readline setup ────────────────────────────────────────────────────────────

def setup_readline(history_file: str = None) -> bool:
    """
    Set up readline with tab completion and history.
    Returns True if readline is available.
    """
    try:
        import readline
        if history_file:
            try:
                readline.read_history_file(history_file)
            except FileNotFoundError:
                pass
            import atexit
            atexit.register(readline.write_history_file, history_file)
        readline.set_history_length(500)
        return True
    except ImportError:
        pass

    # Windows fallback
    if IS_WIN:
        try:
            import pyreadline3  # noqa
            return True
        except ImportError:
            return False

    return False


# ── Python version check ──────────────────────────────────────────────────────

def check_python_version(min_major=3, min_minor=8) -> bool:
    return sys.version_info >= (min_major, min_minor)

def python_version_str() -> str:
    v = sys.version_info
    return f"{v.major}.{v.minor}.{v.micro}"
