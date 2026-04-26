#!/usr/bin/env python3
"""
ReconCLI v3 — main entry point
DSwebTEAM | github.com/DSwebTEAM/ReconCLI
"""

import sys
import os

# Ensure project root is on path whether run as script or installed package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    from core.compat import check_python_version, python_version_str, platform_name

    # Python version gate
    if not check_python_version(3, 8):
        print(f"[!] Python 3.8+ required. You have {python_version_str()}.")
        print(f"    Platform: {platform_name()}")
        sys.exit(1)

    # Handle --version / -v flag before shell loads
    if len(sys.argv) > 1 and sys.argv[1] in ("--version", "-V"):
        print("ReconCLI v3.0.0 | DSwebTEAM")
        sys.exit(0)

    # Handle direct module execution:
    #   reconcli recon/subdomain --target hibiki.app
    if len(sys.argv) > 1 and "/" in sys.argv[1] and not sys.argv[1].startswith("-"):
        _run_direct()
        return

    # Default: launch interactive shell
    from core.shell import Shell
    Shell().start()


def _run_direct():
    """Non-interactive mode: reconcli <engine/module> --target <value> [--opt KEY=VALUE ...]"""
    import argparse
    from core.shell import MODULE_REGISTRY, _load_module
    from core.utils import error, info
    from core.errors import ShellError

    parser = argparse.ArgumentParser(
        prog="reconcli",
        description="ReconCLI v3 — Recon & Security Audit Toolkit",
        epilog="Example: reconcli recon/subdomain --target hibiki.app"
    )
    parser.add_argument("module",          help="Module path  e.g. recon/subdomain")
    parser.add_argument("--target", "-t",  help="Target IP, hostname, or URL", required=True)
    parser.add_argument("--set",    "-s",  nargs="*", metavar="OPT=VAL",
                        help="Set additional options  e.g. --set THREADS=30 WORDLIST=big")
    parser.add_argument("--list",   "-l",  action="store_true",
                        help="List all available modules")

    args = parser.parse_args()

    if args.list:
        print("\n  Available modules:\n")
        for name in sorted(MODULE_REGISTRY.keys()):
            print(f"    {name}")
        print()
        return

    try:
        mod = _load_module(args.module)
    except ShellError as e:
        error(e.message)
        sys.exit(1)

    # Set TARGET
    mod.set_option("TARGET", args.target)

    # Set any extra options
    if args.set:
        for item in args.set:
            if "=" in item:
                key, val = item.split("=", 1)
                mod.set_option(key.upper(), val)
            else:
                error(f"Invalid option format '{item}' — use KEY=VALUE")

    mod.execute()


if __name__ == "__main__":
    main()
