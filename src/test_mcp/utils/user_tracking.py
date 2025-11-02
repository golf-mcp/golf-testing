import json
import os
import tempfile
import threading
import uuid
from datetime import datetime
from pathlib import Path

from .. import __version__
from ..config.config_manager import ConfigManager


class UserTracker:
    """Manages anonymous user identification with thread-safe operations."""

    def __init__(self) -> None:
        self.config_manager = ConfigManager()
        self.user_id_file = (
            self.config_manager.paths.get_system_paths()["cache_dir"] / "user_id.json"
        )
        self._lock = threading.Lock()

    def get_or_create_user_id(self) -> str:
        """
        Get existing or create new anonymous user ID.

        Thread-safe operation that reads or creates a persistent user ID.
        Returns a valid UUID v4 string.
        """
        with self._lock:
            user_id = self._load_existing_user_id()
            if user_id:
                return user_id

            new_user_id = str(uuid.uuid4())
            self._save_user_id(new_user_id)
            return new_user_id

    def _load_existing_user_id(self) -> str | None:
        """Load and validate existing user ID from file."""
        if not self.user_id_file.exists():
            return None

        try:
            data = json.loads(self.user_id_file.read_text(encoding="utf-8"))
            user_id = data.get("user_id")

            if user_id and self._is_valid_uuid(user_id):
                return user_id

        except (json.JSONDecodeError, OSError, KeyError):
            pass

        return None

    def _is_valid_uuid(self, value: str) -> bool:
        """Validate that a string is a proper UUID."""
        try:
            uuid.UUID(value)
            return True
        except (ValueError, AttributeError, TypeError):
            return False

    def _save_user_id(self, user_id: str) -> None:
        """Save user ID to cache file atomically."""
        self.user_id_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "user_id": user_id,
            "created_at": datetime.now().isoformat(),
            "version": __version__,
        }

        self._atomic_write(self.user_id_file, json.dumps(data, indent=2))

    def _atomic_write(self, target_path: Path, content: str) -> None:
        """Write content to file atomically using temp file and rename."""
        temp_fd = None
        temp_path = None

        try:
            temp_fd, temp_path = tempfile.mkstemp(
                dir=target_path.parent, prefix=f".{target_path.name}_", suffix=".tmp"
            )

            os.write(temp_fd, content.encode("utf-8"))
            os.close(temp_fd)
            temp_fd = None

            os.replace(temp_path, target_path)
            temp_path = None

        except OSError as e:
            if temp_fd is not None:
                os.close(temp_fd)
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
            raise OSError(f"Failed to save user ID: {e}") from e


_user_tracker: UserTracker | None = None
_user_tracker_lock = threading.Lock()


def get_user_tracker() -> UserTracker:
    """Get shared user tracker instance using double-checked locking pattern."""
    global _user_tracker

    if _user_tracker is None:
        with _user_tracker_lock:
            if _user_tracker is None:
                _user_tracker = UserTracker()

    return _user_tracker
