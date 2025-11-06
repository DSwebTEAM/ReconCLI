import socket
import requests
import psutil
from rich.console import Console
from rich.table import Table

console = Console()


def get_local_ips():
    """Return list of (interface, IPv4 address) for non-loopback addresses."""
    ips = []
    addrs = psutil.net_if_addrs()
    for iface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ips.append((iface, addr.address))
    return ips


def get_mac_addresses():
    """Return list of (interface, MAC) using platform-appropriate address family."""
    macs = []
    # Determine MAC families across platforms
    mac_families = set()
    if hasattr(socket, "AF_PACKET"):
        mac_families.add(socket.AF_PACKET)  # Linux
    if hasattr(socket, "AF_LINK"):
        mac_families.add(socket.AF_LINK)    # BSD / macOS
    addrs = psutil.net_if_addrs()
    for iface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family in mac_families:
                macs.append((iface, addr.address))
    return macs


def get_interface_status():
    """Return psutil.net_if_stats() result (dict of interface -> stats)."""
    return psutil.net_if_stats()


def show_netinfo():
    """Render network information table to the console."""
    table = Table(title="Network Information", style="bold cyan")
    table.add_column("Property", style="bold green")
    table.add_column("Value", style="bold white")

    hostname = socket.gethostname()

    # Local IPs
    local_ips = get_local_ips()
    local_ip_str = ", ".join([f"{iface}: {ip}" for iface, ip in local_ips]) or "Unavailable"

    # MAC addresses
    mac_addresses = get_mac_addresses()
    mac_str = ", ".join([f"{iface}: {mac}" for iface, mac in mac_addresses]) or "Unavailable"

    # Public IP
    try:
        public_ip = requests.get("https://api.ipify.org", timeout=5).text
    except requests.RequestException:
        public_ip = "Unable to fetch"

    # Interfaces
    interfaces = list(psutil.net_if_addrs().keys())
    interfaces_str = ", ".join(interfaces) or "Unavailable"

    # Interface stats
    stats = get_interface_status()
    stats_str = ", ".join(
        [
            f"{iface}: {'Up' if stat.isup else 'Down'} (Speed: {stat.speed}Mbps)"
            for iface, stat in stats.items()
        ]
    ) or "Unavailable"

    # Network I/O stats
    net_io = psutil.net_io_counters()

    table.add_row("Hostname", hostname)
    table.add_row("Local IPs", local_ip_str)
    table.add_row("MAC Addresses", mac_str)
    table.add_row("Public IP", public_ip)
    table.add_row("Interfaces", interfaces_str)
    table.add_row("Interfaces Status", stats_str)
    table.add_row("Bytes Sent", f"{net_io.bytes_sent / (1024 * 1024):.2f} MB")
    table.add_row("Bytes Received", f"{net_io.bytes_recv / (1024 * 1024):.2f} MB")

    console.print(table)


if __name__ == "__main__":
    show_netinfo()
