import platform
import psutil
from rich.console import Console
from rich.table import Table

console = Console()
table = Table(title="System Information", style="bold cyan")

table.add_column("Property", style="bold green")
table.add_column("Value", style="bold white")

table.add_row("System", platform.system())
table.add_row("Node Name", platform.node())
table.add_row("Release", platform.release())
table.add_row("Version", platform.version())
table.add_row("Machine", platform.machine())
table.add_row("Processor", platform.processor())
table.add_row("CPU Cores", str(psutil.cpu_count(logical=True)))
table.add_row("RAM", f"{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB")

console.print(table)