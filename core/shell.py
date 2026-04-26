"""
core/shell.py — Metasploit-style REPL shell for ReconCLI v3

Prompt:   recon >
Loaded:   recon [recon/subdomain] >

Commands: use, set, options, run, back, sessions,
          findings, export, check, clear, help, exit
"""

import sys
import os
from core.banner  import show_banner, show_help
from core.utils   import color, info, warn, error, success, print_error, divider
from core.compat  import setup_readline, clear_screen, get_sessions_dir, IS_WIN
from core.errors  import ReconCLIError, ShellError


# ── Module registry ───────────────────────────────────────────────────────────
# Maps "engine/name" → (module_path, ClassName)

MODULE_REGISTRY: dict[str, tuple[str, str]] = {
    # Recon
    "recon/portscan":    ("engines.recon.portscan",    "PortScan"),
    "recon/pingsweep":   ("engines.recon.pingsweep",   "PingSweep"),
    "recon/traceroute":  ("engines.recon.traceroute",  "Traceroute"),
    "recon/dns":         ("engines.recon.dns",          "DNSLookup"),
    "recon/subdomain":   ("engines.recon.subdomain",    "SubdomainEnum"),
    "recon/whois":       ("engines.recon.whois",        "WhoisLookup"),
    "recon/headers":     ("engines.recon.headers",      "HeadersGrab"),
    "recon/geoip":       ("engines.recon.geoip",        "GeoIP"),
    "recon/reverseip":   ("engines.recon.reverseip",    "ReverseIP"),
    "recon/asn":         ("engines.recon.asn",          "ASNLookup"),
    "recon/passivedns":  ("engines.recon.passivedns",   "PassiveDNS"),
    "recon/wayback":     ("engines.recon.wayback",      "Wayback"),
    "recon/cloudscan":   ("engines.recon.cloudscan",    "CloudScan"),
    # Analysis
    "analysis/fingerprint": ("engines.analysis.fingerprint", "Fingerprint"),
    "analysis/jsrecon":     ("engines.analysis.jsrecon",     "JSRecon"),
    "analysis/params":      ("engines.analysis.params",      "ParamMiner"),
    "analysis/tlsintel":    ("engines.analysis.tlsintel",    "TLSIntel"),
    "analysis/shield":      ("engines.analysis.shield",      "ShieldDetect"),
    # Security
    "security/cors":          ("engines.security.cors",          "CORSCheck"),
    "security/jwt":           ("engines.security.jwt",           "JWTTester"),
    "security/fileupload":    ("engines.security.fileupload",    "FileUpload"),
    "security/secheaders":    ("engines.security.secheaders",    "SecHeaders"),
    "security/infodisclosure":("engines.security.infodisclosure","InfoDisclosure"),
    "security/csrf":          ("engines.security.csrf",          "CSRFValidator"),
    "security/clickjacking":  ("engines.security.clickjacking",  "ClickjackTester"),
    "security/cookieaudit":   ("engines.security.cookieaudit",   "CookieAudit"),
    "security/dirbust":       ("engines.security.dirbust",       "DirBust"),
    "security/apifuzz":       ("engines.security.apifuzz",       "APIFuzzer"),
    "security/ssl":           ("engines.security.ssl",           "SSLCheck"),
    "security/cve":           ("engines.security.cve",           "CVEScanner"),
}

ALL_MODULE_NAMES = sorted(MODULE_REGISTRY.keys())


# ── Fuzzy suggest ─────────────────────────────────────────────────────────────

def _suggest(name: str, choices: list[str], n: int = 3) -> list[str]:
    """Return closest matches to name from choices."""
    name = name.lower()
    exact = [c for c in choices if name in c]
    if exact:
        return exact[:n]
    # prefix match
    prefix = [c for c in choices if c.startswith(name.split("/")[0])]
    return prefix[:n]


# ── Module loader ─────────────────────────────────────────────────────────────

def _load_module(path: str):
    """Dynamically import and instantiate a module class."""
    import importlib
    if path not in MODULE_REGISTRY:
        suggestions = _suggest(path, ALL_MODULE_NAMES)
        msg = f"Unknown module: '{path}'"
        if suggestions:
            msg += "\n  Did you mean: " + ", ".join(suggestions)
        raise ShellError(msg)

    mod_path, class_name = MODULE_REGISTRY[path]
    try:
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, class_name)
        return cls()
    except ImportError as e:
        raise ShellError(f"Cannot load module '{path}': {e}")
    except AttributeError:
        raise ShellError(f"Module '{path}' missing class '{class_name}'")


# ── Tab completion ─────────────────────────────────────────────────────────────

def _make_completer(module=None):
    root_cmds = [
        "use ", "check", "sessions", "findings",
        "export ", "clear", "help", "exit", "quit"
    ]
    module_cmds = ["set ", "options", "run", "back",
                   "sessions", "findings", "export ", "clear", "help"]

    def completer(text, state):
        try:
            import readline
            line = readline.get_line_buffer()
        except ImportError:
            line = text

        if line.startswith("use "):
            # Complete module names
            partial = line[4:]
            matches = [m + " " for m in ALL_MODULE_NAMES if m.startswith(partial)]
        elif line.startswith("set ") and module:
            # Complete option names
            partial = line[4:]
            matches = [k + " " for k in module.options if k.startswith(partial.upper())]
        elif line.startswith("export "):
            matches = ["export json", "export txt"]
        else:
            cmds = module_cmds if module else root_cmds
            matches = [c for c in cmds if c.startswith(text)]

        return matches[state] if state < len(matches) else None

    return completer


# ── Dependency checker ────────────────────────────────────────────────────────

def run_check():
    """Run the full dependency check and print results."""
    from core.compat import pip_hint, bin_install_hint, find_bin, python_version_str

    section_header = lambda t: print(color(f"\n  ── {t} " + "─" * max(0, 40 - len(t)), "dark"))

    section_header("Python")
    import sys
    pv = python_version_str()
    ok = sys.version_info >= (3, 8)
    print(color(f"  [{'✔' if ok else '✘'}] Python {pv}", "green" if ok else "red"))

    section_header("Python Packages")
    packages = [
        ("requests",     "requests"),
        ("dns.resolver", "dnspython"),
        ("whois",        "python-whois"),
        ("colorama",     "colorama"),
    ]
    for imp, pkg in packages:
        try:
            __import__(imp)
            success(pkg)
        except ImportError:
            error(f"{pkg} — not installed")
            print(color(f"      Fix: {pip_hint(pkg)}", "dark"))

    section_header("System Binaries")
    bins = ["traceroute", "node"]
    for b in bins:
        path = find_bin(b)
        if path:
            success(f"{b}  ({path})")
        else:
            warn(f"{b} — not found")
            print(color(f"      Fix: {bin_install_hint(b)}", "dark"))

    section_header("Connectivity")
    import socket
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        success("Internet connectivity")
    except OSError:
        error("No internet connection")

    print()


# ── Main shell ────────────────────────────────────────────────────────────────

class Shell:
    def __init__(self):
        self._module     = None   # currently loaded BaseModule instance
        self._mod_name   = ""     # e.g. "recon/subdomain"
        self._history_f  = os.path.join(get_sessions_dir(), ".history")

    def _prompt(self) -> str:
        base = color("recon", "red")
        if self._module:
            mod = color(f" [{self._mod_name}]", "cyan")
            return f"\n{base}{mod} {color('>', 'dark')} "
        return f"\n{base} {color('>', 'dark')} "

    def _setup_readline(self):
        try:
            import readline
            readline.set_completer(_make_completer(self._module))
            readline.set_completer_delims(" \t")
            readline.parse_and_bind(
                "tab: complete" if not IS_WIN else "tab: complete"
            )
        except ImportError:
            pass

    # ── Command handlers ──────────────────────────────────────────────────────

    def _cmd_use(self, args: list):
        if not args:
            error("Usage: use <engine/module>")
            return
        path = args[0].lower()
        try:
            self._module   = _load_module(path)
            self._mod_name = path
            success(f"Loaded {color(path, 'cyan')}")
            self._module.show_options()
            self._setup_readline()
        except ShellError as e:
            error(e.message)

    def _cmd_set(self, args: list):
        if not self._module:
            error("No module loaded. Use: use <module>")
            return
        if len(args) < 2:
            error("Usage: set <OPTION> <value>")
            return
        key = args[0]
        val = " ".join(args[1:])
        self._module.set_option(key, val)

    def _cmd_options(self, _):
        if not self._module:
            error("No module loaded.")
            return
        self._module.show_options()

    def _cmd_run(self, _):
        if not self._module:
            error("No module loaded. Use: use <module>")
            return
        self._module.execute()

    def _cmd_back(self, _):
        if self._module:
            info(f"Unloaded {self._mod_name}")
            self._module   = None
            self._mod_name = ""
            self._setup_readline()
        else:
            info("Already at root.")

    def _cmd_sessions(self, _):
        from core.logger import get_session
        get_session().show_sessions()

    def _cmd_findings(self, _):
        from core.logger import get_session
        get_session().show_findings()

    def _cmd_export(self, args: list):
        from core.logger import get_session
        fmt = args[0].lower() if args else "json"
        if fmt == "json":
            get_session().export_json()
        elif fmt == "txt":
            get_session().export_txt()
        else:
            error(f"Unknown format '{fmt}'. Use: export json  or  export txt")

    def _cmd_check(self, _):
        run_check()

    def _cmd_clear(self, _):
        clear_screen()
        show_banner()

    def _cmd_help(self, _):
        show_help()

    def _cmd_exit(self, _):
        print(color("\n  Stay ethical. Goodbye.\n", "yellow"))
        sys.exit(0)

    # ── Dispatch table ────────────────────────────────────────────────────────

    _COMMANDS = {
        "use":      _cmd_use,
        "set":      _cmd_set,
        "options":  _cmd_options,
        "run":      _cmd_run,
        "back":     _cmd_back,
        "sessions": _cmd_sessions,
        "findings": _cmd_findings,
        "export":   _cmd_export,
        "check":    _cmd_check,
        "clear":    _cmd_clear,
        "help":     _cmd_help,
        "exit":     _cmd_exit,
        "quit":     _cmd_exit,
        "q":        _cmd_exit,
    }

    # ── Main loop ─────────────────────────────────────────────────────────────

    def start(self):
        setup_readline(self._history_f)
        self._setup_readline()
        show_banner()
        info(f"{len(MODULE_REGISTRY)} modules loaded  |  type 'help' for commands\n")

        while True:
            try:
                raw = input(self._prompt()).strip()
            except (KeyboardInterrupt, EOFError):
                print()
                self._cmd_exit([])

            if not raw:
                continue

            parts   = raw.split()
            cmd     = parts[0].lower()
            args    = parts[1:]

            handler = self._COMMANDS.get(cmd)
            if handler:
                try:
                    handler(self, args)
                except SystemExit:
                    raise
                except Exception as e:
                    error(f"Shell error: {e}")
            else:
                suggestions = _suggest(cmd, list(self._COMMANDS.keys()))
                error(f"Unknown command: '{cmd}'")
                if suggestions:
                    info(f"Did you mean: {', '.join(suggestions)}")
                info("Type 'help' for available commands.")
