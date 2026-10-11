from rich.console import Console
from rich.markup import escape

console = Console()
err_console = Console(stderr=True)


def print_success(message: str) -> None:
    err_console.print(f"[bold green][+][/bold green] {message}")


def print_error(message: str) -> None:
    err_console.print(f"[bold red][-][/bold red] [red]{escape(str(message))}[/red]")


def print_warning(message: str) -> None:
    err_console.print(f"[bold yellow][!][/bold yellow] [yellow]{message}[/yellow]")


def print_info(message: str) -> None:
    err_console.print(f"[bold cyan][*][/bold cyan] {message}")
