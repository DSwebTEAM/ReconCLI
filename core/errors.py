"""
core/errors.py — Typed exceptions for ReconCLI v3
Every error type has a message + optional fix hint.
"""


class ReconCLIError(Exception):
    """Base exception for all ReconCLI errors."""
    def __init__(self, message: str, hint: str = ""):
        self.message = message
        self.hint    = hint
        super().__init__(message)


class DependencyError(ReconCLIError):
    """A required Python package or binary is missing."""
    def __init__(self, name: str, install_cmd: str = ""):
        self.name        = name
        self.install_cmd = install_cmd
        hint = f"Install with: {install_cmd}" if install_cmd else ""
        super().__init__(f"Missing dependency: {name}", hint)


class TargetError(ReconCLIError):
    """The target provided is invalid or unresolvable."""
    def __init__(self, target: str, reason: str = "", expected: str = ""):
        self.target   = target
        self.expected = expected
        hint = f"Expected format: {expected}" if expected else ""
        super().__init__(f"Invalid target '{target}': {reason}", hint)


class NetworkError(ReconCLIError):
    """A network operation failed."""
    pass


class TimeoutError(NetworkError):
    """Connection or request timed out."""
    def __init__(self, target: str, timeout: float):
        super().__init__(
            f"Timed out connecting to {target} after {timeout}s",
            "Try increasing timeout or check if host is up"
        )


class ConnectionRefusedError(NetworkError):
    """Connection actively refused by host."""
    def __init__(self, target: str, port: int = None):
        port_str = f":{port}" if port else ""
        super().__init__(
            f"Connection refused: {target}{port_str}",
            "Host is up but not accepting connections on this port"
        )


class DNSError(NetworkError):
    """DNS resolution failed."""
    def __init__(self, host: str):
        super().__init__(
            f"Cannot resolve hostname: {host}",
            "Check spelling, or target may be offline / DNS blocked"
        )


class SSLError(NetworkError):
    """SSL/TLS handshake or certificate error."""
    def __init__(self, detail: str):
        super().__init__(
            f"SSL error: {detail}",
            "Certificate may be self-signed, expired, or hostname mismatch"
        )


class ModuleError(ReconCLIError):
    """A module failed during execution."""
    def __init__(self, module: str, reason: str):
        self.module = module
        super().__init__(f"Module '{module}' error: {reason}")


class PermissionError(ReconCLIError):
    """Operation requires elevated privileges."""
    def __init__(self, operation: str):
        hint = "Try running with sudo (Linux/Mac) or as Administrator (Windows)"
        super().__init__(f"Permission denied: {operation}", hint)


class ShellError(ReconCLIError):
    """Shell-level error (bad command, missing options, etc.)."""
    pass
