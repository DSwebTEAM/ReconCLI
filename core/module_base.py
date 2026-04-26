"""
core/module_base.py — Base class for all ReconCLI v3 modules
Every engine module inherits BaseModule. Provides:
  - Standardised options system (set / get / validate)
  - Lazy dependency checking
  - Automatic session logging
  - Consistent error handling
  - Timeout/thread values from compat layer
"""

from abc import ABC, abstractmethod
from core.utils  import (color, info, warn, error, success,
                          section, print_result_header, print_error)
from core.errors import (ReconCLIError, DependencyError,
                          TargetError, ModuleError)
from core.compat import get_timeout, get_threads
from core.logger import get_session


class Option:
    """A single configurable option for a module."""
    def __init__(self, default=None, required: bool = False,
                 description: str = "", kind: str = "str"):
        self.value       = default
        self.default     = default
        self.required    = required
        self.description = description
        self.kind        = kind   # "str" | "int" | "float" | "bool"

    def set(self, raw: str):
        """Set value from raw string input. Converts to correct type."""
        if self.kind == "int":
            try:
                self.value = int(raw)
            except ValueError:
                raise ValueError(f"Expected integer, got: '{raw}'")
        elif self.kind == "float":
            try:
                self.value = float(raw)
            except ValueError:
                raise ValueError(f"Expected number, got: '{raw}'")
        elif self.kind == "bool":
            self.value = raw.lower() in ("true", "yes", "1", "on")
        else:
            self.value = raw

    def display(self) -> str:
        val = self.value if self.value is not None else ""
        req = color(" *", "red") if self.required and not self.value else ""
        return f"{val}{req}"


class BaseModule(ABC):
    """
    Abstract base for all ReconCLI engine modules.

    Subclass and implement:
        name        : str   — e.g. "recon/subdomain"
        description : str   — one-line description
        options     : dict  — {"OPTION_NAME": Option(...)}
        run()       — main logic, use self.opt() to read options
    """

    name:        str = "base/module"
    description: str = "Base module"
    author:      str = "DSwebTEAM"

    def __init__(self):
        # Subclasses define options in their class body or __init__
        if not hasattr(self, "options"):
            self.options: dict[str, Option] = {}

        # Always add TARGET option if not defined
        if "TARGET" not in self.options:
            self.options["TARGET"] = Option(
                required=True,
                description="Target IP, hostname, or URL"
            )

        self._timeout = get_timeout()
        self._threads = get_threads()
        self._run     = None   # current session run dict

    # ── Option access ─────────────────────────────────────────────────────────

    def opt(self, key: str):
        """Get current value of an option."""
        key = key.upper()
        if key not in self.options:
            raise KeyError(f"Unknown option: {key}")
        return self.options[key].value

    def set_option(self, key: str, value: str) -> bool:
        """Set an option by name. Returns True on success."""
        key = key.upper()
        if key not in self.options:
            error(f"Unknown option '{key}' for module {self.name}")
            return False
        try:
            self.options[key].set(value)
            print(color(f"  {key}", "cyan") + color(f" => {value}", "white"))
            return True
        except ValueError as e:
            error(str(e))
            return False

    def show_options(self):
        """Print the options table for this module."""
        section(f"Options — {self.name}")
        print(color(
            f"  {'OPTION':<18} {'VALUE':<28} {'REQUIRED':<10} DESCRIPTION",
            "dark"
        ))
        print(color("  " + "─" * 72, "dark"))
        for name, opt in self.options.items():
            req  = color("yes", "red") if opt.required else color("no", "dark")
            val  = color(str(opt.value) if opt.value is not None else "(not set)", "white")
            desc = color(opt.description, "dark")
            print(f"  {color(name, 'cyan'):<27} {val:<37} {req:<19} {desc}")
        print()

    def validate_options(self) -> bool:
        """Check all required options are set. Returns True if ok."""
        missing = [k for k, o in self.options.items()
                   if o.required and not o.value]
        if missing:
            for m in missing:
                error(f"Required option not set: {m}")
                info(f"  → set {m} <value>")
            return False
        return True

    # ── Execution ─────────────────────────────────────────────────────────────

    def execute(self):
        """
        Called by the shell when user types 'run'.
        Wraps run() with validation, logging, and error handling.
        """
        if not self.validate_options():
            return

        session = get_session()
        self._run = session.start_run(self.name, self.opt("TARGET") or "")

        print_result_header(self.name, self.opt("TARGET") or "")

        try:
            self.run()
            session.finish_run(self._run, "ok", self._run.get("summary", ""))
        except ReconCLIError as e:
            print_error(e)
            session.finish_run(self._run, "error", str(e))
        except KeyboardInterrupt:
            warn("Interrupted by user.")
            session.finish_run(self._run, "interrupted")
        except Exception as e:
            error(f"Unexpected error in {self.name}: {e}")
            if hasattr(self, "_verbose") and self._verbose:
                import traceback
                traceback.print_exc()
            session.finish_run(self._run, "error", str(e))

    @abstractmethod
    def run(self):
        """Module logic. Read options with self.opt('OPTION_NAME')."""
        ...

    # ── Logging helpers (call from run()) ─────────────────────────────────────

    def finding(self, severity: str, title: str, detail: str = ""):
        """Record a finding to the session log."""
        if self._run:
            get_session().add_finding(self._run, severity, title, detail)

    def critical(self, title: str, detail: str = ""):
        self.finding("CRITICAL", title, detail)
        error(f"CRITICAL: {title}")
        if detail: print(color(f"    → {detail}", "dark"))

    def high(self, title: str, detail: str = ""):
        self.finding("HIGH", title, detail)
        from core.utils import warn as _warn
        _warn(f"HIGH: {title}")
        if detail: print(color(f"    → {detail}", "dark"))

    def medium(self, title: str, detail: str = ""):
        self.finding("MEDIUM", title, detail)
        info(f"MEDIUM: {title}")

    def low(self, title: str, detail: str = ""):
        self.finding("LOW", title, detail)

    def note(self, title: str, detail: str = ""):
        self.finding("INFO", title, detail)

    # ── Dependency helpers ────────────────────────────────────────────────────

    def need_package(self, import_name: str, pip_name: str = None):
        """Lazy-import a package. Raises DependencyError if missing."""
        from core.utils import require_package
        return require_package(import_name, pip_name)

    def need_bin(self, binary: str):
        """Check a binary exists. Raises DependencyError if not."""
        from core.utils import require_bin
        require_bin(binary)
