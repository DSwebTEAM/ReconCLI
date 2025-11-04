# modules/sysinfo.py
import platform import socket import psutil from rich.console import Console from rich.table import Table console = Console() def 
get_sysinfo():
    console.print("[cyan bold]System Information[/cyan bold]\n") table = Table(show_header=True, header_style="bold magenta") 
    table.add_column("Property", style="cyan") table.add_column("Value", style="green") uname = platform.uname() 
    table.add_row("System", uname.system) table.add_row("Node Name", uname.node) table.add_row("Release", uname.release) 
    table.add_row("Version", uname.version) table.add_row("Machine", uname.machine) table.add_row("Processor", uname.processor)
    # IP and Memory info
    try: hostname = socket.gethostname() ip = socket.gethostbyname(hostname) table.add_row("IP Address", ip) except: table.add_row("IP 
        Address", "Unavailable")
    memory = psutil.virtual_memory() table.add_row("Total RAM", f"{round(memory.total / (1024 ** 3), 2)} GB") console.print(table) if 
__name__ == "__main__":
    get_sysinfo()
