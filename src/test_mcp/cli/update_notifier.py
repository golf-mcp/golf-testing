import threading
from datetime import datetime, timedelta

from ..config.config_manager import ConfigManager
from ..shared.console_shared import get_console
from ..utils.version_checker import VersionChecker


class UpdateNotifier:
    """Handles version update notifications with smart display logic"""

    def __init__(self):
        self.config_manager = ConfigManager()
        self.console = get_console()
        self.version_checker = VersionChecker()

    def check_and_notify_if_needed(self):
        """Main entry point - check for updates and notify if appropriate"""
        if not self._should_show_notification():
            return

        # Run check asynchronously
        self.version_checker.check_for_update_async(self._handle_check_result)

    def _should_show_notification(self) -> bool:
        """Determine if we should show update notification"""
        if not self.config_manager.should_check_for_updates():
            return False

        # Check cooldown period
        config = self.config_manager.get_update_config()
        cooldown_hours = config.get("notification_cooldown_hours", 24)

        last_notification = config.get("last_notification")
        if last_notification:
            try:
                last_time = datetime.fromisoformat(last_notification)
                if datetime.now() - last_time < timedelta(hours=cooldown_hours):
                    return False  # Still in cooldown period
            except Exception:
                pass  # Ignore invalid timestamps

        return True

    def _handle_check_result(self, result: dict | None):
        """Handle the result of version check"""
        if not result or not result.get("has_update"):
            return

        # Update last notification time
        config = self.config_manager.get_update_config()
        config["last_notification"] = datetime.now().isoformat()
        self.config_manager.save_update_config(config)

        # Display notification
        self._display_update_notification(result)

    def _display_update_notification(self, result: dict):
        """Display update notification using shared console system"""
        current = result["current_version"]
        latest = result["latest_version"]

        # Use shared console method instead of manual formatting
        self.console.print_update_notification(current, latest)


# Global instance
_update_notifier: UpdateNotifier | None = None
_update_notifier_lock = threading.Lock()


def get_update_notifier() -> UpdateNotifier:
    """Get shared update notifier instance"""
    global _update_notifier
    if _update_notifier is None:  # First check (optimization)
        with _update_notifier_lock:
            if _update_notifier is None:  # Second check (safety)
                _update_notifier = UpdateNotifier()
    return _update_notifier


def check_for_updates():
    """Convenience function for CLI integration"""
    try:
        notifier = get_update_notifier()
        notifier.check_and_notify_if_needed()
    except Exception:
        # Silently fail - never break user workflow
        pass
