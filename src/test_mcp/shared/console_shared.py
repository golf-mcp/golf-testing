"""Unified console system for consistent CLI output formatting"""

import threading
from enum import Enum

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table


class MessageType(Enum):
    """Standard message types with consistent styling"""

    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    COMMAND = "command"
    HEADER = "header"
    UPDATE = "update"


class MCPConsole:
    """Unified console with consistent Rich formatting patterns"""

    def __init__(self, force_terminal: bool | None = None):
        """Initialize console with TTY detection"""
        self.console = Console(force_terminal=force_terminal)
        self._setup_styles()

    def _setup_styles(self):
        """Define consistent color schemes and styles"""
        self.styles = {
            MessageType.SUCCESS: "green",
            MessageType.ERROR: "red",
            MessageType.WARNING: "yellow",
            MessageType.INFO: "blue",
            MessageType.COMMAND: "cyan",
            MessageType.HEADER: "bold blue",
            MessageType.UPDATE: "bold blue",
        }

        self.icons = {
            MessageType.SUCCESS: "✅",
            MessageType.ERROR: "❌",
            MessageType.WARNING: "⚠️",
            MessageType.INFO: "💡",
            MessageType.UPDATE: "📦",
        }

    def print_message(
        self, message: str, msg_type: MessageType, include_icon: bool = True
    ) -> None:
        """Print styled message with consistent formatting"""
        style = self.styles[msg_type]
        icon = self.icons.get(msg_type, "") if include_icon else ""
        icon_part = f"{icon} " if icon else ""

        self.console.print(f"[{style}]{icon_part}{message}[/{style}]")

    def print_success(self, message: str) -> None:
        """Print success message"""
        self.print_message(message, MessageType.SUCCESS)

    def print_error(self, message: str, suggestions: list[str] | None = None) -> None:
        """Print error message with optional suggestions"""
        self.print_message(message, MessageType.ERROR)
        if suggestions:
            self.console.print("[yellow]💡 Suggestions:[/yellow]")
            for suggestion in suggestions:
                self.console.print(f"  [dim]• {suggestion}[/dim]")

    def print_warning(self, message: str) -> None:
        """Print warning message"""
        self.print_message(message, MessageType.WARNING)

    def print_info(self, message: str) -> None:
        """Print info message"""
        self.print_message(message, MessageType.INFO)

    def print_command(self, command: str, description: str = "") -> None:
        """Print command with consistent highlighting"""
        desc_part = f" - {description}" if description else ""
        self.console.print(f"  [cyan]{command}[/cyan][dim]{desc_part}[/dim]")

    def print_header(self, text: str) -> None:
        """Print section header"""
        self.print_message(text, MessageType.HEADER, include_icon=False)

    def create_config_table(
        self, items: dict[str, dict], config_type: str = "Configuration"
    ) -> Table:
        """Create standardized configuration table"""
        table = Table()

        # Determine column name based on config type
        if config_type.lower() == "test suite":
            id_column_name = "Suite ID"
        elif config_type.lower() == "server":
            id_column_name = "Server ID"
        else:
            id_column_name = "ID"

        table.add_column(id_column_name, style="cyan", no_wrap=True)

        # Add columns based on config type
        if config_type.lower() == "server":
            table.add_column("Details", style="dim")
            table.add_column("Transport", style="dim", justify="center")
            table.add_column("OAuth", style="dim", justify="center")
            table.add_column("Creation Date", style="dim", justify="center")
        elif config_type.lower() == "test suite":
            table.add_column("Tests", style="dim", justify="left")
            table.add_column("Creation Date", style="dim", justify="center")
        else:
            table.add_column("Details", style="dim")

        for item_id, item_info in items.items():
            # Create details string based on config type
            if config_type.lower() == "server":
                details = item_info.get("url", "No URL")
                transport = item_info.get("transport", "http")
                oauth = "Yes" if item_info.get("oauth", False) else "No"
                creation_date = item_info.get("creation_date", "Unknown")
                table.add_row(item_id, details, transport, oauth, creation_date)
            elif config_type.lower() == "test suite":
                test_count = item_info.get("test_count", 0)
                creation_date = item_info.get("creation_date", "Unknown")
                table.add_row(item_id, str(test_count), creation_date)
            else:
                details = item_info.get("type", "unknown")
                table.add_row(item_id, details)

        return table

    def create_results_panel(
        self, title: str, content: str, success: bool = True
    ) -> Panel:
        """Create standardized results panel"""
        border_style = "green" if success else "red"
        return Panel(content, title=title, border_style=border_style)

    def create_progress_tracker(
        self, total_tasks: int, description: str = "Processing"
    ) -> Progress:
        """Create standardized progress tracker"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        )

    def confirm(self, message: str, default: bool = True) -> bool:
        """Standardized confirmation prompt"""
        return Confirm.ask(message, default=default, console=self.console)

    def prompt(self, message: str, default: str | None = None) -> str:
        """Standardized text prompt"""
        if default is not None:
            return Prompt.ask(message, default=default, console=self.console)
        else:
            return Prompt.ask(message, console=self.console)

    def print_json(self, data):
        """Print JSON data with consistent formatting"""
        # Handle Pydantic models and other non-serializable objects
        if hasattr(data, "model_dump"):
            # Pydantic v2
            json_data = data.model_dump()
        elif hasattr(data, "dict"):
            # Pydantic v1
            json_data = data.dict()
        else:
            json_data = data
        self.console.print_json(data=json_data)

    def print_update_notification(
        self, current_version: str, latest_version: str
    ) -> None:
        """Display update notification using Rich Panel"""
        content = f"""Current version: [red]{current_version}[/red]
Latest version:  [green]{latest_version}[/green]

[cyan]pip install --upgrade mcp-testing[/cyan]

[dim]To disable these notifications:[/dim]
[dim]  export NO_UPDATE_NOTIFIER=1[/dim]"""

        panel = Panel(
            content, title="📦 Update Available", border_style="blue", padding=(0, 1)
        )
        self.console.print()  # Add spacing
        self.console.print(panel)
        self.console.print()

    def print(self, *args, **kwargs):
        """Direct access to Rich console.print for backward compatibility"""
        self.console.print(*args, **kwargs)


# Global console instance
_console_instance: MCPConsole | None = None
_console_instance_lock = threading.Lock()


def get_console() -> MCPConsole:
    """Get shared console instance"""
    global _console_instance
    if _console_instance is None:  # First check (optimization)
        with _console_instance_lock:
            if _console_instance is None:  # Second check (safety)
                _console_instance = MCPConsole()
    return _console_instance
