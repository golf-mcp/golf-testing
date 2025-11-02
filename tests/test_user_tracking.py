"""
Comprehensive tests for UserTracker functionality.

Tests cover:
- User ID creation and persistence
- UUID validation
- Thread safety
- Error handling
- Atomic file operations
- Edge cases
"""

import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

import pytest

from src.test_mcp.utils.user_tracking import UserTracker, get_user_tracker


@pytest.fixture
def temp_cache_dir(tmp_path):
    """Create a temporary cache directory for testing."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture
def mock_config_manager(temp_cache_dir):
    """Mock ConfigManager to use temporary directory."""
    mock_manager = MagicMock()
    mock_manager.paths.get_system_paths.return_value = {"cache_dir": temp_cache_dir}
    return mock_manager


@pytest.fixture
def user_tracker(mock_config_manager):
    """Create UserTracker instance with mocked config."""
    with patch(
        "src.test_mcp.utils.user_tracking.ConfigManager",
        return_value=mock_config_manager,
    ):
        tracker = UserTracker()
    return tracker


class TestUserTrackerBasics:
    """Test basic UserTracker functionality."""

    def test_initialization(self, user_tracker, temp_cache_dir):
        """Test UserTracker initializes correctly."""
        assert user_tracker.user_id_file == temp_cache_dir / "user_id.json"
        assert hasattr(user_tracker, "_lock")
        assert isinstance(user_tracker._lock, type(threading.Lock()))

    def test_create_new_user_id(self, user_tracker):
        """Test creating a new user ID when none exists."""
        user_id = user_tracker.get_or_create_user_id()

        assert user_id is not None
        assert isinstance(user_id, str)
        assert user_tracker._is_valid_uuid(user_id)

    def test_user_id_persisted_to_file(self, user_tracker):
        """Test user ID is saved to file correctly."""
        user_id = user_tracker.get_or_create_user_id()

        assert user_tracker.user_id_file.exists()

        data = json.loads(user_tracker.user_id_file.read_text())
        assert data["user_id"] == user_id
        assert "created_at" in data
        assert "version" in data

    def test_load_existing_user_id(self, user_tracker):
        """Test loading existing user ID from file."""
        first_id = user_tracker.get_or_create_user_id()
        second_id = user_tracker.get_or_create_user_id()

        assert first_id == second_id

    def test_user_id_consistent_across_instances(self, mock_config_manager):
        """Test same user ID is returned across different tracker instances."""
        with patch(
            "src.test_mcp.utils.user_tracking.ConfigManager",
            return_value=mock_config_manager,
        ):
            tracker1 = UserTracker()
            user_id1 = tracker1.get_or_create_user_id()

            tracker2 = UserTracker()
            user_id2 = tracker2.get_or_create_user_id()

        assert user_id1 == user_id2


class TestUUIDValidation:
    """Test UUID validation functionality."""

    def test_valid_uuid_v4(self, user_tracker):
        """Test valid UUID v4 strings are accepted."""
        valid_uuid = str(uuid.uuid4())
        assert user_tracker._is_valid_uuid(valid_uuid) is True

    def test_valid_uuid_v1(self, user_tracker):
        """Test valid UUID v1 strings are accepted."""
        valid_uuid = str(uuid.uuid1())
        assert user_tracker._is_valid_uuid(valid_uuid) is True

    def test_invalid_uuid_string(self, user_tracker):
        """Test invalid UUID strings are rejected."""
        invalid_uuids = [
            "not-a-uuid",
            "12345",
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "123e4567-e89b-12d3-a456-42661417400",  # Too short
            "",
            "123e4567-e89b-12d3-a456-426614174000-extra",  # Too long
        ]

        for invalid in invalid_uuids:
            assert user_tracker._is_valid_uuid(invalid) is False

    def test_non_string_uuid(self, user_tracker):
        """Test non-string values are rejected."""
        assert user_tracker._is_valid_uuid(None) is False
        assert user_tracker._is_valid_uuid(123) is False
        assert user_tracker._is_valid_uuid([]) is False

    def test_uuid_with_uppercase(self, user_tracker):
        """Test UUID with uppercase letters is valid."""
        valid_uuid = "550E8400-E29B-41D4-A716-446655440000"
        assert user_tracker._is_valid_uuid(valid_uuid) is True


class TestFileHandling:
    """Test file operations and error handling."""

    def test_creates_parent_directory(self, user_tracker):
        """Test parent directory is created if it doesn't exist."""
        parent_dir = user_tracker.user_id_file.parent
        if parent_dir.exists():
            import shutil

            shutil.rmtree(parent_dir)

        user_tracker.get_or_create_user_id()

        assert parent_dir.exists()
        assert user_tracker.user_id_file.exists()

    def test_handles_corrupted_json(self, user_tracker):
        """Test handles corrupted JSON file gracefully."""
        user_tracker.user_id_file.parent.mkdir(parents=True, exist_ok=True)
        user_tracker.user_id_file.write_text("{ invalid json }")

        user_id = user_tracker.get_or_create_user_id()

        assert user_id is not None
        assert user_tracker._is_valid_uuid(user_id)

    def test_handles_empty_file(self, user_tracker):
        """Test handles empty file gracefully."""
        user_tracker.user_id_file.parent.mkdir(parents=True, exist_ok=True)
        user_tracker.user_id_file.write_text("")

        user_id = user_tracker.get_or_create_user_id()

        assert user_id is not None
        assert user_tracker._is_valid_uuid(user_id)

    def test_handles_missing_user_id_field(self, user_tracker):
        """Test handles JSON without user_id field."""
        user_tracker.user_id_file.parent.mkdir(parents=True, exist_ok=True)
        data = {"created_at": "2024-01-01", "version": "1.0.0"}
        user_tracker.user_id_file.write_text(json.dumps(data))

        user_id = user_tracker.get_or_create_user_id()

        assert user_id is not None
        assert user_tracker._is_valid_uuid(user_id)

    def test_handles_invalid_uuid_in_file(self, user_tracker):
        """Test handles invalid UUID in file."""
        user_tracker.user_id_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "user_id": "not-a-valid-uuid",
            "created_at": "2024-01-01",
            "version": "1.0.0",
        }
        user_tracker.user_id_file.write_text(json.dumps(data))

        user_id = user_tracker.get_or_create_user_id()

        assert user_id is not None
        assert user_tracker._is_valid_uuid(user_id)
        assert user_id != "not-a-valid-uuid"

    def test_handles_null_user_id(self, user_tracker):
        """Test handles null user_id in file."""
        user_tracker.user_id_file.parent.mkdir(parents=True, exist_ok=True)
        data = {"user_id": None, "created_at": "2024-01-01", "version": "1.0.0"}
        user_tracker.user_id_file.write_text(json.dumps(data))

        user_id = user_tracker.get_or_create_user_id()

        assert user_id is not None
        assert user_tracker._is_valid_uuid(user_id)


class TestAtomicWrite:
    """Test atomic write operations."""

    def test_atomic_write_creates_file(self, user_tracker, temp_cache_dir):
        """Test atomic write creates file correctly."""
        test_file = temp_cache_dir / "test.json"
        content = '{"test": "data"}'

        user_tracker._atomic_write(test_file, content)

        assert test_file.exists()
        assert test_file.read_text() == content

    def test_atomic_write_overwrites_existing(self, user_tracker, temp_cache_dir):
        """Test atomic write overwrites existing file."""
        test_file = temp_cache_dir / "test.json"
        test_file.write_text("old content")

        new_content = '{"test": "new data"}'
        user_tracker._atomic_write(test_file, new_content)

        assert test_file.read_text() == new_content

    def test_atomic_write_cleanup_on_error(self, user_tracker, temp_cache_dir):
        """Test temporary file is cleaned up on error."""
        test_file = temp_cache_dir / "test.json"

        with patch("os.write", side_effect=OSError("Disk full")):
            with pytest.raises(OSError, match="Failed to save user ID"):
                user_tracker._atomic_write(test_file, "content")

        temp_files = list(temp_cache_dir.glob(".test.json_*.tmp"))
        assert len(temp_files) == 0

    def test_atomic_write_with_unicode(self, user_tracker, temp_cache_dir):
        """Test atomic write handles unicode content."""
        test_file = temp_cache_dir / "test.json"
        content = '{"emoji": "🎉", "chinese": "你好"}'

        user_tracker._atomic_write(test_file, content)

        assert test_file.read_text(encoding="utf-8") == content

    def test_no_partial_writes(self, user_tracker, temp_cache_dir):
        """Test file is not partially written on failure."""
        test_file = temp_cache_dir / "test.json"
        original_content = "original"
        test_file.write_text(original_content)

        call_count = 0

        def failing_write(fd, data):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSError("Write failed")

        with patch("os.write", side_effect=failing_write):
            with pytest.raises(OSError):
                user_tracker._atomic_write(test_file, "new content")

        assert test_file.read_text() == original_content


class TestThreadSafety:
    """Test thread safety of UserTracker operations."""

    def test_concurrent_get_or_create(self, user_tracker):
        """Test concurrent get_or_create_user_id calls return same ID."""
        user_ids = []

        def get_user_id():
            user_id = user_tracker.get_or_create_user_id()
            user_ids.append(user_id)

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(get_user_id) for _ in range(50)]
            for future in futures:
                future.result()

        assert len(set(user_ids)) == 1

    def test_single_instance_no_race_condition(self, user_tracker):
        """Test single tracker instance prevents race conditions."""
        user_ids = set()

        def get_id_multiple_times():
            for _ in range(10):
                user_id = user_tracker.get_or_create_user_id()
                user_ids.add(user_id)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(get_id_multiple_times) for _ in range(10)]
            for future in futures:
                future.result()

        assert len(user_ids) == 1

    def test_concurrent_read_write(self, user_tracker):
        """Test concurrent reads during write operations."""
        results = []
        errors = []

        def read_or_write(i):
            try:
                user_id = user_tracker.get_or_create_user_id()
                results.append(user_id)
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(read_or_write, i) for i in range(100)]
            for future in futures:
                future.result()

        assert len(errors) == 0
        assert len(set(results)) == 1
        assert all(user_tracker._is_valid_uuid(uid) for uid in results)


class TestSingletonPattern:
    """Test singleton pattern for get_user_tracker()."""

    def test_returns_same_instance(self):
        """Test get_user_tracker returns same instance."""
        tracker1 = get_user_tracker()
        tracker2 = get_user_tracker()

        assert tracker1 is tracker2

    def test_singleton_thread_safe(self):
        """Test singleton pattern is thread-safe."""
        instances = []

        def get_instance():
            tracker = get_user_tracker()
            instances.append(id(tracker))

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(get_instance) for _ in range(100)]
            for future in futures:
                future.result()

        assert len(set(instances)) == 1


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_very_long_path(self, mock_config_manager, tmp_path):
        """Test handles very long file paths."""
        long_dir = tmp_path / ("x" * 100) / ("y" * 100)
        mock_config_manager.paths.get_system_paths.return_value = {
            "cache_dir": long_dir
        }

        with patch(
            "src.test_mcp.utils.user_tracking.ConfigManager",
            return_value=mock_config_manager,
        ):
            tracker = UserTracker()
            user_id = tracker.get_or_create_user_id()

        assert tracker._is_valid_uuid(user_id)

    def test_file_with_special_characters_in_path(self, mock_config_manager, tmp_path):
        """Test handles paths with special characters."""
        special_dir = tmp_path / "test-dir_123" / "sub.dir"
        mock_config_manager.paths.get_system_paths.return_value = {
            "cache_dir": special_dir
        }

        with patch(
            "src.test_mcp.utils.user_tracking.ConfigManager",
            return_value=mock_config_manager,
        ):
            tracker = UserTracker()
            user_id = tracker.get_or_create_user_id()

        assert tracker._is_valid_uuid(user_id)

    def test_readonly_parent_directory(self, user_tracker):
        """Test handles read-only parent directory."""
        user_tracker.user_id_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            os.chmod(user_tracker.user_id_file.parent, 0o444)

            with pytest.raises(OSError):
                user_tracker.get_or_create_user_id()
        finally:
            os.chmod(user_tracker.user_id_file.parent, 0o755)  # noqa: S103

    def test_existing_file_with_extra_fields(self, user_tracker):
        """Test handles file with extra fields gracefully."""
        user_tracker.user_id_file.parent.mkdir(parents=True, exist_ok=True)
        valid_uuid = str(uuid.uuid4())
        data = {
            "user_id": valid_uuid,
            "created_at": "2024-01-01",
            "version": "1.0.0",
            "extra_field": "should be ignored",
            "another_field": 12345,
        }
        user_tracker.user_id_file.write_text(json.dumps(data))

        user_id = user_tracker.get_or_create_user_id()

        assert user_id == valid_uuid


class TestMetadata:
    """Test metadata storage in user ID file."""

    def test_stores_created_at_timestamp(self, user_tracker):
        """Test created_at timestamp is stored."""
        from datetime import datetime

        before = datetime.now()
        user_tracker.get_or_create_user_id()
        after = datetime.now()

        data = json.loads(user_tracker.user_id_file.read_text())
        created_at = datetime.fromisoformat(data["created_at"])

        assert before <= created_at <= after

    def test_stores_version(self, user_tracker):
        """Test version is stored in file."""
        from src.test_mcp import __version__

        user_tracker.get_or_create_user_id()

        data = json.loads(user_tracker.user_id_file.read_text())
        assert data["version"] == __version__

    def test_json_formatting(self, user_tracker):
        """Test JSON file is properly formatted with indentation."""
        user_tracker.get_or_create_user_id()

        content = user_tracker.user_id_file.read_text()

        assert content.count("\n") > 1
        assert "  " in content
