"""engines/recon/portscan.py — TCP port scanner with banner grabbing."""

import socket
import concurrent.futures
from core.module_base import BaseModule, Option
from core.utils       import color, info, success, warn, section
from core.validator   import require_host
from core.errors      import DNSError
from core.compat      import get_timeout, get_threads

COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 6379:"Redis",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 27017:"MongoDB",
    9200:"Elasticsearch", 5000:"Flask/Dev", 3000:"Node/Dev",
    4000:"Dev", 8000:"Dev", 8888:"Jupyter", 6060:"Dev",
}

RISKY = {
    22:"SSH exposed to internet",
    3306:"MySQL port open — auth required?",
    6379:"Redis exposed — often no auth by default",
    27017:"MongoDB exposed — often no auth by default",
    9200:"Elasticsearch exposed — no auth by default",
    5432:"PostgreSQL exposed",
    23:"Telnet — unencrypted, replace with SSH",
}


class PortScan(BaseModule):
    name        = "recon/portscan"
    description = "TCP port scanner with banner grabbing and risk flagging"

    def __init__(self):
        self.options = {
            "TARGET":  Option(required=True,  description="Hostname or IP address"),
            "PORTS":   Option(default="common", description="'common' or range like 1-1024"),
            "TIMEOUT": Option(default=str(get_timeout()), description="Socket timeout (seconds)", kind="float"),
            "THREADS": Option(default=str(get_threads()), description="Concurrent threads", kind="int"),
        }
        super().__init__()

    def _get_ports(self) -> list:
        spec = self.opt("PORTS") or "common"
        if spec == "common":
            return list(COMMON_PORTS.keys())
        if "-" in spec:
            try:
                start, end = spec.split("-")
                return list(range(int(start), int(end) + 1))
            except ValueError:
                warn(f"Invalid port range '{spec}', using common ports")
                return list(COMMON_PORTS.keys())
        try:
            return [int(p.strip()) for p in spec.split(",")]
        except ValueError:
            warn(f"Invalid port spec '{spec}', using common ports")
            return list(COMMON_PORTS.keys())

    def _grab_banner(self, ip: str, port: int) -> str:
        try:
            s = socket.socket()
            s.settimeout(1.0)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(256).decode(errors="ignore").strip().split("\n")[0]
            s.close()
            return banner[:70]
        except Exception:
            return ""

    def _scan_port(self, ip: str, port: int, timeout: float) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            return result == 0
        except Exception:
            return False

    def run(self):
        target  = require_host(self.opt("TARGET"))
        timeout = float(self.opt("TIMEOUT"))
        threads = int(self.opt("THREADS"))
        ports   = self._get_ports()

        # Resolve
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            raise DNSError(target)

        if ip != target:
            info(f"Resolved {target} → {ip}")
        info(f"Scanning {len(ports)} port(s)  threads={threads}  timeout={timeout}s\n")

        open_ports = []

        def check(port):
            if self._scan_port(ip, port, timeout):
                open_ports.append(port)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            ex.map(check, ports)

        if not open_ports:
            warn("No open ports found.")
            return

        section("Open Ports")
        print(color(f"  {'PORT':<8} {'SERVICE':<18} BANNER", "dark"))
        print(color("  " + "─" * 56, "dark"))

        for port in sorted(open_ports):
            service = COMMON_PORTS.get(port, "Unknown")
            banner  = self._grab_banner(ip, port)
            print(
                color(f"  {port:<8}", "cyan") +
                color(f"{service:<18}", "green") +
                color(banner, "dark")
            )
            self.note(f"Open port {port}/{service}", banner)

        success(f"{len(open_ports)} open port(s) found.")

        # Risk flags
        risky_found = [(p, RISKY[p]) for p in open_ports if p in RISKY]
        if risky_found:
            section("Risk Flags")
            for port, msg in risky_found:
                self.high(f"Port {port} — {msg}")
