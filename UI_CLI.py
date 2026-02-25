from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
import system_status
import time

def run_ui(event_queue):
    alerts = []
    stats = {"packets":0, "alerts":0}

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )

    def table():
        t = Table(title="IPS Alerts")
        t.add_column("Time")
        t.add_column("Attack")
        t.add_column("IP")
        t.add_column("Severity")

        for a in alerts[-10:]:
            color = "red" if a["severity"]=="HIGH" else "yellow"
            t.add_row(a["time"], a["attack"], a["ip"], f"[{color}]{a['severity']}[/]")

        return t

    try:
        with Live(layout, refresh_per_second=4):
            while system_status.running:
                while not event_queue.empty():
                    e = event_queue.get()
                    if e["type"]=="alert":
                        alerts.append(e)
                        stats["alerts"]+=1
                    if e["type"]=="packet":
                        stats["packets"]+=1

                header = f"IPS RUNNING | Packets:{stats['packets']} Alerts:{stats['alerts']}"
                layout["header"].update(Panel(header, style="bold green"))
                layout["body"].update(table())
                time.sleep(0.1)
    except KeyboardInterrupt:
        system_status.running = False
