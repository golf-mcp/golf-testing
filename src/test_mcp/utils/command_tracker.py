import json
import re
import threading
from datetime import datetime

from ..config.config_manager import ConfigManager
from ..models.reporting import CommandHistoryEntry


class CommandTracker:
    """Tracks command execution history for debugging context"""

    def __init__(self, max_history: int = 25):
        self.config_manager = ConfigManager()
        self.history_file = (
            self.config_manager.paths.get_system_paths()["cache_dir"]
            / "command_history.json"
        )
        self.max_history = max_history

    def _sanitize_command(self, command: str) -> str:
        """Sanitize command for privacy before sending to cloud"""
        # Remove full system paths and keep only the essential command structure
        if not command:
            return command

        # Split command into parts to preserve arguments
        parts = command.split()
        if not parts:
            return command

        # Replace full path to mcp-t executable with just "mcp-t"
        if (
            parts[0].endswith("/mcp-t")
            or parts[0].endswith("\\mcp-t")
            or "mcp-t" in parts[0]
        ):
            parts[0] = "mcp-t"

        # Process remaining arguments to remove sensitive paths
        sanitized_parts = [parts[0]]  # Keep the command name

        for part in parts[1:]:
            # Replace user home directories
            sanitized_part = re.sub(r"/Users/[^/\s]+", "~", part)
            # Replace other absolute paths that might be sensitive
            sanitized_part = re.sub(
                r"/[a-zA-Z0-9._-]+/[a-zA-Z0-9._/-]+/bin/", "", sanitized_part
            )
            # Keep the argument if it's not empty after sanitization
            if sanitized_part.strip():
                sanitized_parts.append(sanitized_part.strip())

        return " ".join(sanitized_parts)

    def record_command(
        self,
        command: str,
        exit_code: int | None = None,
        duration_ms: float | None = None,
    ):
        """Record a command execution"""
        # Sanitize command for privacy before storing
        sanitized_command = self._sanitize_command(command)

        entry = CommandHistoryEntry(
            command=sanitized_command,
            timestamp=datetime.now(),
            exit_code=exit_code,
            duration_ms=duration_ms,
        )

        history = self._load_history()
        history.append(entry)

        # Keep only recent entries
        history = history[-self.max_history :]
        self._save_history(history)

    def get_recent_history(self, limit: int = 10) -> list[CommandHistoryEntry]:
        """Get recent command history"""
        history = self._load_history()
        return history[-limit:] if history else []

    def _load_history(self) -> list[CommandHistoryEntry]:
        """Load command history from file"""
        if not self.history_file.exists():
            return []

        try:
            data = json.loads(self.history_file.read_text())
            return [CommandHistoryEntry(**entry) for entry in data]
        except Exception:
            return []  # Return empty on corruption

    def _save_history(self, history: list[CommandHistoryEntry]):
        """Save command history to file"""
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        data = [entry.model_dump(mode="json") for entry in history]
        self.history_file.write_text(json.dumps(data, indent=2, default=str))


# Global instance
_command_tracker: CommandTracker | None = None
_command_tracker_lock = threading.Lock()


def get_command_tracker() -> CommandTracker:
    """Get shared command tracker instance"""
    global _command_tracker
    if _command_tracker is None:  # First check (optimization)
        with _command_tracker_lock:
            if _command_tracker is None:  # Second check (safety)
                _command_tracker = CommandTracker()
    return _command_tracker
