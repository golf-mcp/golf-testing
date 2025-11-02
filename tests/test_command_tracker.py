"""Tests for command tracking functionality"""

import json
import pytest
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch

from src.test_mcp.utils.command_tracker import CommandTracker, get_command_tracker
from src.test_mcp.models.reporting import CommandHistoryEntry


class TestCommandTracker:
    """Test CommandTracker class"""

    @pytest.fixture
    def temp_cache_dir(self):
        """Create a temporary cache directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def tracker(self, temp_cache_dir):
        """Create a CommandTracker with temporary cache directory"""
        with patch("src.test_mcp.utils.command_tracker.ConfigManager") as mock_config:
            mock_instance = Mock()
            mock_instance.paths.get_system_paths.return_value = {
                "cache_dir": temp_cache_dir
            }
            mock_config.return_value = mock_instance
            return CommandTracker()

    def test_initialization(self, tracker):
        """Test CommandTracker initialization"""
        assert tracker.max_history == 25
        assert tracker.history_file.name == "command_history.json"

    def test_initialization_custom_max_history(self, temp_cache_dir):
        """Test initialization with custom max_history"""
        with patch("src.test_mcp.utils.command_tracker.ConfigManager") as mock_config:
            mock_instance = Mock()
            mock_instance.paths.get_system_paths.return_value = {
                "cache_dir": temp_cache_dir
            }
            mock_config.return_value = mock_instance
            tracker = CommandTracker(max_history=50)
            assert tracker.max_history == 50

    def test_sanitize_command_basic(self, tracker):
        """Test basic command sanitization"""
        command = "mcp-t run suite.json"
        sanitized = tracker._sanitize_command(command)
        assert sanitized == "mcp-t run suite.json"

    def test_sanitize_command_full_path(self, tracker):
        """Test sanitization of full path to mcp-t"""
        command = "/usr/local/bin/mcp-t run suite.json"
        sanitized = tracker._sanitize_command(command)
        assert sanitized == "mcp-t run suite.json"

    def test_sanitize_command_windows_path(self, tracker):
        """Test sanitization of Windows path to mcp-t"""
        command = "C:\\Users\\test\\bin\\mcp-t run suite.json"
        sanitized = tracker._sanitize_command(command)
        assert sanitized == "mcp-t run suite.json"

    def test_sanitize_command_user_home(self, tracker):
        """Test sanitization of user home directory"""
        command = "mcp-t run /Users/john/config/suite.json"
        sanitized = tracker._sanitize_command(command)
        assert "john" not in sanitized
        assert "~" in sanitized

    def test_sanitize_command_empty(self, tracker):
        """Test sanitization of empty command"""
        assert tracker._sanitize_command("") == ""

    def test_sanitize_command_complex(self, tracker):
        """Test sanitization of complex command with multiple arguments"""
        command = "/usr/local/bin/mcp-t run --parallel 4 /Users/test/suite.json"
        sanitized = tracker._sanitize_command(command)
        assert sanitized.startswith("mcp-t")
        assert "--parallel" in sanitized
        assert "4" in sanitized
        assert "/usr/local/bin" not in sanitized

    def test_record_command_basic(self, tracker):
        """Test recording a basic command"""
        tracker.record_command("mcp-t run suite.json")
        history = tracker.get_recent_history()

        assert len(history) == 1
        assert history[0].command == "mcp-t run suite.json"
        assert history[0].exit_code is None
        assert history[0].duration_ms is None
        assert isinstance(history[0].timestamp, datetime)

    def test_record_command_with_exit_code(self, tracker):
        """Test recording command with exit code"""
        tracker.record_command("mcp-t run suite.json", exit_code=0)
        history = tracker.get_recent_history()

        assert len(history) == 1
        assert history[0].exit_code == 0

    def test_record_command_with_duration(self, tracker):
        """Test recording command with duration"""
        tracker.record_command("mcp-t run suite.json", duration_ms=1234.5)
        history = tracker.get_recent_history()

        assert len(history) == 1
        assert history[0].duration_ms == 1234.5

    def test_record_command_with_all_fields(self, tracker):
        """Test recording command with all fields"""
        tracker.record_command(
            "mcp-t run suite.json", exit_code=0, duration_ms=1234.5
        )
        history = tracker.get_recent_history()

        assert len(history) == 1
        assert history[0].command == "mcp-t run suite.json"
        assert history[0].exit_code == 0
        assert history[0].duration_ms == 1234.5

    def test_record_multiple_commands(self, tracker):
        """Test recording multiple commands"""
        tracker.record_command("mcp-t run suite1.json")
        tracker.record_command("mcp-t run suite2.json")
        tracker.record_command("mcp-t run suite3.json")

        history = tracker.get_recent_history()
        assert len(history) == 3
        assert history[0].command == "mcp-t run suite1.json"
        assert history[1].command == "mcp-t run suite2.json"
        assert history[2].command == "mcp-t run suite3.json"

    def test_get_recent_history_limit(self, tracker):
        """Test getting recent history with limit"""
        for i in range(15):
            tracker.record_command(f"mcp-t run suite{i}.json")

        history = tracker.get_recent_history(limit=5)
        assert len(history) == 5
        # Should get the most recent 5
        assert history[0].command == "mcp-t run suite10.json"
        assert history[4].command == "mcp-t run suite14.json"

    def test_max_history_enforcement(self, tracker):
        """Test that history is limited to max_history entries"""
        tracker.max_history = 10

        # Record more commands than max_history
        for i in range(20):
            tracker.record_command(f"mcp-t run suite{i}.json")

        history = tracker.get_recent_history(limit=100)
        assert len(history) == 10
        # Should only keep the last 10
        assert history[0].command == "mcp-t run suite10.json"
        assert history[9].command == "mcp-t run suite19.json"

    def test_load_history_nonexistent_file(self, tracker):
        """Test loading history when file doesn't exist"""
        history = tracker._load_history()
        assert history == []

    def test_save_and_load_history(self, tracker):
        """Test saving and loading history from file"""
        tracker.record_command("mcp-t run suite.json", exit_code=0)

        # Create a new tracker instance with same cache dir
        with patch("src.test_mcp.utils.command_tracker.ConfigManager") as mock_config:
            mock_instance = Mock()
            mock_instance.paths.get_system_paths.return_value = {
                "cache_dir": tracker.history_file.parent
            }
            mock_config.return_value = mock_instance
            new_tracker = CommandTracker()

        # Should load existing history
        history = new_tracker.get_recent_history()
        assert len(history) == 1
        assert history[0].command == "mcp-t run suite.json"
        assert history[0].exit_code == 0

    def test_load_history_corrupted_file(self, tracker):
        """Test loading history from corrupted file returns empty list"""
        # Create corrupted JSON file
        tracker.history_file.parent.mkdir(parents=True, exist_ok=True)
        tracker.history_file.write_text("corrupted{json")

        history = tracker._load_history()
        assert history == []

    def test_save_history_creates_directory(self, tracker):
        """Test that saving history creates parent directory if needed"""
        # Ensure directory doesn't exist
        if tracker.history_file.parent.exists():
            tracker.history_file.unlink(missing_ok=True)
            tracker.history_file.parent.rmdir()

        tracker.record_command("mcp-t run suite.json")

        assert tracker.history_file.exists()
        assert tracker.history_file.parent.exists()

    def test_get_recent_history_empty(self, tracker):
        """Test getting history when none exists"""
        history = tracker.get_recent_history()
        assert history == []

    def test_command_sanitization_preserves_arguments(self, tracker):
        """Test that sanitization preserves command arguments"""
        command = "mcp-t run --parallel 4 --timeout 30 suite.json"
        tracker.record_command(command)
        history = tracker.get_recent_history()

        assert "--parallel" in history[0].command
        assert "4" in history[0].command
        assert "--timeout" in history[0].command
        assert "30" in history[0].command

    def test_history_persistence(self, tracker):
        """Test that history persists across tracker instances"""
        # Record in first tracker
        tracker.record_command("mcp-t run suite1.json", exit_code=0)
        tracker.record_command("mcp-t run suite2.json", exit_code=1)

        # Create second tracker with same cache dir
        with patch("src.test_mcp.utils.command_tracker.ConfigManager") as mock_config:
            mock_instance = Mock()
            mock_instance.paths.get_system_paths.return_value = {
                "cache_dir": tracker.history_file.parent
            }
            mock_config.return_value = mock_instance
            tracker2 = CommandTracker()

        # Add more commands
        tracker2.record_command("mcp-t run suite3.json", exit_code=0)

        # Should have all commands
        history = tracker2.get_recent_history()
        assert len(history) == 3

    def test_history_file_format(self, tracker):
        """Test that history file has correct JSON format"""
        tracker.record_command("mcp-t run suite.json", exit_code=0, duration_ms=100.5)

        # Read raw file content
        content = json.loads(tracker.history_file.read_text())

        assert isinstance(content, list)
        assert len(content) == 1
        assert "command" in content[0]
        assert "timestamp" in content[0]
        assert "exit_code" in content[0]
        assert "duration_ms" in content[0]


class TestGetCommandTracker:
    """Test get_command_tracker singleton function"""

    def test_returns_same_instance(self):
        """Test that get_command_tracker returns the same instance"""
        tracker1 = get_command_tracker()
        tracker2 = get_command_tracker()
        assert tracker1 is tracker2

    def test_thread_safe_initialization(self):
        """Test that singleton initialization is thread-safe"""
        import threading

        # Reset global tracker
        import src.test_mcp.utils.command_tracker as ct_module
        ct_module._command_tracker = None

        trackers = []

        def get_tracker():
            trackers.append(get_command_tracker())

        threads = [threading.Thread(target=get_tracker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All threads should get the same instance
        assert len(set(id(t) for t in trackers)) == 1

