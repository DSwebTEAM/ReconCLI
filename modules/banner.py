import os
import random
from rich.console import Console

console = Console()

def show_banner():
    os.system("clear")

    # Path to your banner text
    banner_path = os.path.join(os.path.dirname(__file__), '../data/banners/recon.txt')
    try:
        with open(banner_path, 'r') as f:
            banner_text = f.read()
    except FileNotFoundError:
        banner_text = "ReconCLI"

    # Print with colors
    console.print(f"[cyan]{banner_text}[/cyan]")
    console.print("[magenta bold]by DS Labs[/magenta bold]")
    console.print("[white]Lightweight Ethical Recon Toolkit[/white]")
    console.print("[blue]─────────────────────────────────────────────[/blue]\n")

    # Random quote
    quotes = [
    "Scanning minds, not machines.",
    "Think before you scan.",
    "Ethics first. Recon next.",
    "Knowledge is your best defense."
]
    console.print(f"[yellow]{random.choice(quotes)}[/yellow]\n")

if __name__ == "__main__":
    show_banner()
