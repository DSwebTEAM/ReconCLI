"""
core/banner.py — Adaptive banner and help display for ReconCLI v3
"""

import shutil
from core.utils import color

VERSION = "v3.0.0"
AUTHOR  = "DSwebTEAM"
WARNING = "Authorized use on own systems ONLY."

_BANNER_WIDE = r"""
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗██╗     ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║     ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║     ██║     ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║     ██║     ██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║╚██████╗███████╗██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝"""

_BANNER_MED = r"""
  ____                      _____ _     ___
 |  _ \ ___  ___ ___  _ __ / ____| |   |_ _|
 | |_) / _ \/ __/ _ \| '_ \ |    | |    | |
 |  _ <  __/ (_| (_) | | | | |___| |___ | |
 |_| \_\___|\___\___/|_| |_|\____|_____|___|"""

_BANNER_NARROW = "  [ ReconCLI v3 ]"


def _cols() -> int:
    return shutil.get_terminal_size((80, 20)).columns

def _div(width: int = None) -> str:
    w = min((width or _cols()) - 4, 60)
    return color("  " + "─" * max(w, 10), "dark")

def show_banner():
    cols = _cols()
    if cols >= 70:
        art = _BANNER_WIDE
    elif cols >= 45:
        art = _BANNER_MED
    else:
        art = _BANNER_NARROW

    print(color(art, "red"))
    print(_div())

    meta  = f"  {VERSION}  |  {AUTHOR}  |  github.com/DSwebTEAM/ReconCLI"
    alert = f"  ! {WARNING}"
    meta  = meta[:cols - 2] if cols < len(meta) else meta
    alert = alert[:cols - 2] if cols < len(alert) else alert

    print(color(meta,  "cyan"))
    print(color(alert, "yellow"))
    print(_div())
    print()


def show_help():
    """Print shell command reference."""
    cols = _cols()
    print(color("\n  Shell Commands\n", "yellow"))
    cmds = [
        ("use <engine/module>",   "Load a module  e.g. use recon/subdomain"),
        ("set <OPTION> <value>",  "Set an option  e.g. set TARGET hibiki.app"),
        ("options",               "Show current module options"),
        ("run",                   "Run the loaded module"),
        ("back",                  "Unload module, return to root prompt"),
        ("sessions",              "List all runs this session"),
        ("findings",              "Show all findings this session"),
        ("export json|txt",       "Export session report"),
        ("check",                 "Check all dependencies"),
        ("clear",                 "Clear the screen"),
        ("help",                  "Show this help"),
        ("exit / quit",           "Exit ReconCLI"),
    ]
    for cmd, desc in cmds:
        print(color(f"  {cmd:<28}", "cyan") + color(desc, "dark"))

    print(color("\n  Modules\n", "yellow"))
    engines = [
        ("recon/",    ["portscan","pingsweep","traceroute","dns","subdomain",
                       "whois","headers","geoip","reverseip",
                       "asn","passivedns","wayback","cloudscan"]),
        ("analysis/", ["fingerprint","jsrecon","params","tlsintel","shield"]),
        ("security/", ["cors","jwt","fileupload","secheaders","infodisclosure",
                       "csrf","clickjacking","cookieaudit","dirbust",
                       "apifuzz","ssl","cve"]),
    ]
    for prefix, mods in engines:
        print(color(f"  {prefix}", "yellow"))
        # Wrap module names across terminal width
        line = "    "
        for m in mods:
            entry = f"{prefix}{m}  "
            if len(line) + len(entry) > cols - 4:
                print(color(line, "dark"))
                line = "    "
            line += entry
        if line.strip():
            print(color(line, "dark"))
    print()
