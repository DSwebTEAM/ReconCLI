"""
Safety helpers for ReconCLI.

Responsibilities:
- Input sanitization (hosts, urls)
- Consent handling for active operations
- Safe subprocess execution with whitelist/timeout/output caps
- Audit logging (JSON-lines)
- Small helper utilities for other modules to call
"""

import os
import json
import re
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from getpass import getuser
import sys
import stat
import time
from typing import List, Tuple

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
except Exception:
    Console = Panel = Text = None

console = Console() if Console else None

# Log paths
HOME = Path.home()
LOG_DIR = HOME / ".reconcli" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
SAFETY_LOG = LOG_DIR / "safety.log"

# Default whitelist of allowed external commands (only executable basenames)
DEFAULT_WHITELIST = {"whois", "curl", "wget", "dig"}


def _audit_log(action, details):
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "user": getuser(),
        "action": action,
        "details": details,
    }
    try:
        with SAFETY_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        # Best-effort logging; do not crash main flow
        pass


def _cprint(msg, style=None):
    if console:
        console.print(msg if style is None else Text(str(msg), style=style))
    else:
        print(msg)


def show_consent_prompt(target, reason=None):
    """
    Ask for explicit consent for active operations on a non-local target.
    Returns True if user confirms, False otherwise.
    """
    if Panel:
        _cprint(
            Panel(
                f"[bold red]Ethics Notice[/bold red]\nYou are about to run active checks against: [bold]{target}[/bold]\nUse only on systems you own or have written permission to test.",
                title="Consent Required",
            )
        )
    else:
        _cprint(
            f"Consent Required: You are about to run active checks against: {target}. Use only on systems you own or have permission to test."
        )

    if reason:
        _cprint(f"[yellow]Reason:[/yellow] {reason}")

    while True:
        try:
            ans = input("Type 'YES' to confirm consent (or 'no' to cancel): ").strip()
        except (KeyboardInterrupt, EOFError):
            _audit_log("consent_denied", {"target": target, "reason": reason})
            return False

        if ans == "YES":
            _audit_log("consent_granted", {"target": target, "reason": reason})
            return True
        if ans.lower() in ("no", "n", ""):
            _audit_log("consent_denied", {"target": target, "reason": reason})
            return False
        _cprint("Please type 'YES' or 'no'.")


IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_ipv4(addr):
    if not addr or not IPV4_RE.match(addr):
        return False
    parts = addr.split(".")
    try:
        return all(0 <= int(p) < 256 for p in parts)
    except ValueError:
        return False


def is_domain(host):
    if not host:
        return False
    return bool(DOMAIN_RE.match(host))


def sanitize_target(raw):
    """
    Normalize and sanitize target strings:
      - strip schemes (http/https)
      - strip trailing slash and path
      - remove default ports if present
      - return hostname or IPv4
    """
    if not raw:
        return ""
    t = raw.strip()
    t = re.sub(r"^https?://", "", t, flags=re.I)
    t = t.split("/", 1)[0]
    if ":" in t:
        host, port = t.split(":", 1)
        if port.isdigit():
            t = host
    return t


def is_localhost(target):
    t = sanitize_target(target).lower()
    return t in ("localhost", "127.0.0.1", "::1")


def require_consent_for_target(target, reason=None, force=False):
    """
    Convenience wrapper to require consent for any non-local target.
    If force=True, require consent even for localhost.
    Returns True if we have consent, False otherwise.
    """
    t = sanitize_target(target)
    if not t:
        return False
    if is_localhost(t) and not force:
        return True
    return show_consent_prompt(t, reason=reason)


class SafeExecutionError(Exception):
    pass


def run_safe_command(cmd, whitelist=None, timeout=20, max_output_bytes=10000, dry_run=False):
    """
    Execute an external command safely.
    - cmd: string or list
    - whitelist: set of allowed executable basenames (overrides default)
    - timeout: seconds
    - max_output_bytes: truncate output to this many bytes
    - dry_run: if True, only logs and returns the to-be-run command

    Returns a dict: {ok: bool, returncode: int, stdout: str, stderr: str, cmd: str}
    """
    if isinstance(cmd, (list, tuple)):
        parts = [str(x) for x in cmd]
    else:
        parts = shlex.split(str(cmd))

    if not parts:
        raise SafeExecutionError("Empty command")

    exe = os.path.basename(parts[0])
    allowed = set(DEFAULT_WHITELIST) if whitelist is None else set(whitelist)
    if exe not in allowed:
        raise SafeExecutionError(f"Executable '{exe}' not allowed by whitelist")

    cmd_str = " ".join(shlex.quote(p) for p in parts)
    audit_details = {"cmd": cmd_str, "exe": exe, "timeout": timeout, "dry_run": bool(dry_run)}
    _audit_log("run_safe_command_request", audit_details)

    if dry_run:
        _cprint(f"[yellow]DRY RUN:[/yellow] {cmd_str}")
        return {"ok": True, "returncode": None, "stdout": "", "stderr": "", "cmd": cmd_str}

    try:
        p = subprocess.Popen(parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
            _audit_log("run_safe_command_timeout", {"cmd": cmd_str})
            return {
                "ok": False,
                "returncode": None,
                "stdout": (out or "")[:max_output_bytes],
                "stderr": "Timed out",
                "cmd": cmd_str,
            }

        out = (out or "")[:max_output_bytes]
        err = (err or "")[:max_output_bytes]
        _audit_log("run_safe_command_executed", {"cmd": cmd_str, "returncode": p.returncode})
        return {"ok": p.returncode == 0, "returncode": p.returncode, "stdout": out, "stderr": err, "cmd": cmd_str}
    except Exception as e:
        _audit_log("run_safe_command_failed", {"cmd": cmd_str, "error": str(e)})
        raise SafeExecutionError(str(e))


def mask_sensitive(text, keep_last=6):
    """
    Mask API keys, long hex strings and emails in `text` for safe output.
    Very simple approach — replace long hex-like tokens with masked version.
    """
    if not text:
        return text
    masked = re.sub(r"\b[0-9a-fA-F]{12,}\b", lambda m: "..." + m.group(0)[-keep_last:], text)
    masked = re.sub(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", r"\1@...REDACTED...", masked)
    return masked


def ensure_active_ok(target, reason=None, force=False):
    """
    Use from other modules before doing active checks:
      if not ensure_active_ok(target, reason="portscan"): return False
    """
    ok = require_consent_for_target(target, reason=reason, force=force)
    if not ok:
        _cprint("[red]Consent not given. Aborting active operation.[/red]")
    return ok


def tail_audit(n=20):
    try:
        text = SAFETY_LOG.read_text(encoding="utf-8")
        lines = text.splitlines()
        for line in lines[-n:]:
            try:
                obj = json.loads(line)
                _cprint(obj)
            except Exception:
                _cprint(line)
    except FileNotFoundError:
        _cprint("No safety log found.")


def _find_sensitive_files(base: Path) -> List[Path]:
    """Simple heuristic: filenames with 'backup' or ending with .zip/.bak/.old"""
    hits = []
    for root, _, files in os.walk(base):
        for f in files:
            if "backup" in f.lower() or f.lower().endswith((".zip", ".bak", ".old")):
                hits.append(Path(root) / f)
    return hits


def _find_world_readable_keys(base: Path) -> List[Path]:
    """Find files under a 'keys' directory that are world-readable."""
    hits = []
    for root, _, files in os.walk(base):
        if Path(root).name.lower() == "keys" or "keys" in Path(root).parts:
            for f in files:
                p = Path(root) / f
                try:
                    mode = p.stat().st_mode
                    if bool(mode & stat.S_IROTH):
                        hits.append(p)
                except Exception:
                    continue
    return hits


def _check_env_file_for_secrets(env_path: Path) -> Tuple[bool, List[str]]:
    """Return (has_secrets, list_of_matches). Very small heuristic."""
    if not env_path.exists():
        return False, []
    matches = []
    try:
        for ln in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if re.search(r"(?:PASSWORD|SECRET|API[_-]?KEY|TOKEN)\s*=", ln, flags=re.I):
                matches.append(ln.strip())
    except Exception:
        pass
    return (len(matches) > 0), matches


def _check_file_permissions_safe(p: Path) -> bool:
    """Return True if file is not world-readable and not world-writable."""
    try:
        mode = p.stat().st_mode
        if mode & (stat.S_IROTH | stat.S_IWOTH):
            return False
        return True
    except Exception:
        return False


def _check_virtualenv_active() -> bool:
    """Detect if running inside a virtualenv (VIRTUAL_ENV or prefix/base_prefix)."""
    if os.environ.get("VIRTUAL_ENV"):
        return True
    try:
        import sys as _sys

        if getattr(_sys, "base_prefix", None) and _sys.base_prefix != _sys.prefix:
            return True
    except Exception:
        pass
    return False


def _check_python_env_ok(min_major=3, min_minor=8) -> Tuple[bool, str]:
    v = sys.version_info
    ok = (v.major > min_major) or (v.major == min_major and v.minor >= min_minor)
    ver = f"{v.major}.{v.minor}.{v.micro}"
    return ok, ver


def run_security_scan(base: str = None) -> dict:
    """
    Run a simple, fast security scan of the repository/workspace.
    Prints a concise summary to stdout (matches requested format) and writes a report file.
    Returns a dict with results.
    """
    start = time.time()
    base_path = Path(base) if base else Path.cwd()

    print("[+] Starting Security Scan...")

    py_ok, py_ver = _check_python_env_ok()
    if py_ok:
        print(f"[✓] Python environment: OK ({py_ver})")
    else:
        print(f"[!] Python environment: Outdated ({py_ver})")

    venv_active = _check_virtualenv_active()
    if venv_active:
        print("[✓] Virtual environment active")
    else:
        print("[!] Virtual environment not detected")

    # File scans
    sensitive = _find_sensitive_files(base_path)
    if sensitive:
        # list first hit in-line, rest omitted for brevity
        print(f"[!] Found {len(sensitive)} sensitive file(s): {sensitive[0].relative_to(base_path)}")
    else:
        print("[✓] No obvious sensitive backup files found")

    world_keys = _find_world_readable_keys(base_path)
    if world_keys:
        print(f"[!] Detected world-readable key file: {world_keys[0].relative_to(base_path)}")
    else:
        print("[✓] No world-readable key files detected")

    env_path = base_path / ".env"
    has_secrets, secret_lines = _check_env_file_for_secrets(env_path)
    if has_secrets:
        print(f"[!] Exposed credentials in .env: {len(secret_lines)} items")
    else:
        print("[✓] No exposed credentials in .env")

    main_py = base_path / "main.py"
    if main_py.exists() and _check_file_permissions_safe(main_py):
        print("[✓] Safe permissions on main.py")
    elif main_py.exists():
        print("[!] main.py has unsafe permissions")
    else:
        print("[✓] main.py not present (skipped)")

    elapsed = time.time() - start
    print(f"[+] Scan completed in {elapsed:.1f} seconds.\n")

    # Summary
    total_files = sum(len(files) for _, _, files in os.walk(base_path))
    issues = 0
    issue_items = []
    if sensitive:
        issues += len(sensitive)
        issue_items.append(("Sensitive files", sensitive))
    if world_keys:
        issues += len(world_keys)
        issue_items.append(("World-readable keys", world_keys))
    if has_secrets:
        issues += len(secret_lines)
        issue_items.append((".env exposed items", secret_lines))
    severity = "Medium" if issues else "Low"

    # Prepare report text
    today = datetime.utcnow().date().isoformat()
    report_name = f"safety_report_{today}.txt"
    report_path = LOG_DIR / report_name
    report_lines = []
    report_lines.append("Security Scan Report")
    report_lines.append(f"Workspace: {base_path}")
    report_lines.append(f"Started: {datetime.utcnow().isoformat()}Z")
    report_lines.append(f"Elapsed: {elapsed:.1f} seconds")
    report_lines.append("")
    report_lines.append("Findings:")
    if not issue_items:
        report_lines.append("  - No issues found.")
    else:
        for title, items in issue_items:
            report_lines.append(f"  - {title}: {len(items)}")
            for it in items[:10]:
                report_lines.append(f"      • {it}")
            if len(items) > 10:
                report_lines.append(f"      • ... and {len(items)-10} more")
    report_lines.append("")
    report_lines.append("Summary:")
    report_lines.append(f"  • Total files scanned: {total_files}")
    report_lines.append(f"    • Issues found: {issues}")
    report_lines.append(f"      • Severity: {severity}")
    report_lines.append(f"        • Log saved to: {report_path.relative_to(HOME.parent) if report_path.exists() else ('logs/' + report_name)}")
    report_lines.append("")
    report_lines.append("Tip: Fix file permissions and delete unused backups.")
    report_text = "\n".join(report_lines)

    try:
        report_path.write_text(report_text, encoding="utf-8")
    except Exception:
        # fallback to writing into LOG_DIR with best effort filename
        try:
            alt = LOG_DIR / f"safety_report_{int(time.time())}.txt"
            alt.write_text(report_text, encoding="utf-8")
            report_path = alt
        except Exception:
            pass

    # Print the summary block matching requested layout
    print("Summary:")
    print(f"  • Total files scanned: {total_files}")
    print(f"    • Issues found: {issues}")
    print(f"      • Severity: {severity}")
    print(f"        • Log saved to: logs/{report_path.name}\n")
    print("Tip: Fix file permissions and delete unused backups.")

    # Audit log and return results
    _audit_log("security_scan_completed", {"base": str(base_path), "elapsed_s": elapsed, "issues": issues, "report": str(report_path)})
    return {
        "base": str(base_path),
        "elapsed": elapsed,
        "total_files": total_files,
        "issues": issues,
        "report": str(report_path),
    }


__all__ = [
    "sanitize_target",
    "is_localhost",
    "require_consent_for_target",
    "ensure_active_ok",
    "run_safe_command",
    "mask_sensitive",
    "tail_audit",
    "SafeExecutionError",
    "run_security_scan",
]