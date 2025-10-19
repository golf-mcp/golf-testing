"""
Stress tests for singleton race conditions and thread safety

These tests validate that all singleton implementations are thread-safe
and prevent race conditions under high concurrency.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from src.test_mcp.services.reporting_client import get_reporting_client
from src.test_mcp.shared.console_shared import get_console
from src.test_mcp.shared.progress_tracker import ProgressTracker
from src.test_mcp.utils.command_tracker import get_command_tracker
from src.test_mcp.utils.user_tracking import get_user_tracker


class TestSingletonThreadSafety:
    """Stress tests for singleton race conditions"""

    def test_reporting_client_singleton(self):
        """Test reporting client singleton under high concurrency"""
        results = []

        def access_singleton():
            client = get_reporting_client()
            results.append(id(client))

        # Run with 50 concurrent threads
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(access_singleton) for _ in range(100)]
            for future in futures:
                future.result()

        # Verify all threads got the same instance (same object ID)
        assert len(set(results)) == 1, (
            "Multiple instances created - race condition detected!"
        )

    def test_console_singleton(self):
        """Test console singleton under high concurrency"""
        results = []

        def access_singleton():
            console = get_console()
            results.append(id(console))

        # Run with 50 concurrent threads
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(access_singleton) for _ in range(100)]
            for future in futures:
                future.result()

        # Verify all threads got the same instance
        assert len(set(results)) == 1, (
            "Multiple instances created - race condition detected!"
        )

    def test_command_tracker_singleton(self):
        """Test command tracker singleton under high concurrency"""
        results = []

        def access_singleton():
            tracker = get_command_tracker()
            results.append(id(tracker))

        # Run with 50 concurrent threads
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(access_singleton) for _ in range(100)]
            for future in futures:
                future.result()

        # Verify all threads got the same instance
        assert len(set(results)) == 1, (
            "Multiple instances created - race condition detected!"
        )

    def test_user_tracker_singleton(self):
        """Test user tracker singleton under high concurrency"""
        results = []

        def access_singleton():
            tracker = get_user_tracker()
            results.append(id(tracker))

        # Run with 50 concurrent threads
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(access_singleton) for _ in range(100)]
            for future in futures:
                future.result()

        # Verify all threads got the same instance
        assert len(set(results)) == 1, (
            "Multiple instances created - race condition detected!"
        )

    def test_all_singletons_together(self):
        """Test all singletons simultaneously under high concurrency"""
        results = {
            "reporting": [],
            "console": [],
            "command_tracker": [],
            "user_tracker": [],
        }

        def access_all_singletons():
            # Access all singletons simultaneously
            reporting = get_reporting_client()
            console = get_console()
            tracker = get_command_tracker()
            user_tracker = get_user_tracker()

            results["reporting"].append(id(reporting))
            results["console"].append(id(console))
            results["command_tracker"].append(id(tracker))
            results["user_tracker"].append(id(user_tracker))

        # Run with 50 concurrent threads accessing all singletons
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(access_all_singletons) for _ in range(100)]
            for future in futures:
                future.result()

        # Verify each singleton returned same instance across all threads
        for name, ids in results.items():
            unique_ids = set(ids)
            assert len(unique_ids) == 1, (
                f"{name} created multiple instances - race condition detected!"
            )


class TestProgressTrackerThreadSafety:
    """Test ProgressTracker thread safety under concurrent access"""

    def test_concurrent_progress_updates(self):
        """Test concurrent progress updates don't corrupt state"""
        tracker = ProgressTracker(total_tests=100, parallelism=10)

        def update_progress(test_id):
            # Simulate multiple updates to same test
            for i in range(5):
                tracker.update_simple_progress(
                    f"test_{test_id}", f"Step {i}", completed=(i == 4)
                )
                time.sleep(0.001)  # Small delay to increase contention

        # Run 20 threads updating progress concurrently
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(update_progress, i) for i in range(20)]
            for future in futures:
                future.result()

        # Verify all tests were tracked
        assert len(tracker.test_progress) == 20

    def test_parallel_test_progress_updates(self):
        """Test update_parallel_test_progress() under concurrency"""
        tracker = ProgressTracker(total_tests=50, parallelism=5)

        def update_parallel_progress(test_id):
            for step in range(3):
                tracker.update_parallel_test_progress(
                    f"parallel_test_{test_id}",
                    step_description=f"Processing step {step}",
                    current_step=step,
                    total_steps=3,
                    completed=(step == 2),
                )
                time.sleep(0.001)

        # Run 10 concurrent updates
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(update_parallel_progress, i) for i in range(10)]
            for future in futures:
                future.result()

        # Verify all tests tracked correctly
        assert len(tracker.test_progress) == 10

    def test_status_table_generation_during_updates(self):
        """Test generate_status_table() is safe during concurrent updates"""
        tracker = ProgressTracker(total_tests=20, parallelism=5)
        tables_generated = []

        def update_tests():
            for i in range(10):
                tracker.update_simple_progress(f"test_{i}", f"Running {i}")
                time.sleep(0.001)

        def generate_tables():
            for _ in range(20):
                table = tracker.generate_status_table()
                tables_generated.append(table)
                time.sleep(0.001)

        # Run updates and table generation concurrently
        with ThreadPoolExecutor(max_workers=2) as executor:
            update_future = executor.submit(update_tests)
            table_future = executor.submit(generate_tables)

            update_future.result()
            table_future.result()

        # Verify tables were generated without errors
        assert len(tables_generated) == 20


class TestFileNamingCollisions:
    """Test file naming prevents collisions under concurrent creation"""

    def test_timestamp_uniqueness(self):
        """Verify timestamp-based file names are unique when created concurrently"""
        import uuid
        from datetime import datetime

        filenames = []

        def generate_filename():
            # Simulate the file naming pattern from utils.py
            datetime_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")[:-3]
            unique_id = str(uuid.uuid4())[:8]
            run_id = str(uuid.uuid4())
            filename = f"{datetime_str}_{unique_id}_{run_id}"
            filenames.append(filename)

        # Create 100 filenames concurrently
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(generate_filename) for _ in range(100)]
            for future in futures:
                future.result()

        # Verify all filenames are unique
        assert len(set(filenames)) == 100, "Duplicate filenames detected!"

    def test_suite_id_uniqueness(self):
        """Verify suite IDs are unique when generated concurrently"""
        import uuid
        from datetime import datetime

        suite_ids = []

        def generate_suite_id(server_id):
            # Simulate suite ID generation from generation_commands.py
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]
            unique_id = uuid.uuid4().hex[:8]
            suite_id = f"{server_id}-generated-{timestamp}-{unique_id}"
            suite_ids.append(suite_id)

        # Generate 100 suite IDs concurrently
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(generate_suite_id, "test_server") for _ in range(100)
            ]
            for future in futures:
                future.result()

        # Verify all suite IDs are unique
        assert len(set(suite_ids)) == 100, "Duplicate suite IDs detected!"


@pytest.mark.slow
class TestStressTests:
    """Extended stress tests for high-load scenarios"""

    def test_extreme_concurrency(self):
        """Test singleton access under extreme concurrency (100+ threads)"""
        results = []

        def access_singletons():
            reporting = get_reporting_client()
            console = get_console()
            results.append((id(reporting), id(console)))

        # Run with 100 concurrent threads
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(access_singletons) for _ in range(200)]
            for future in futures:
                future.result()

        # Verify consistency
        first_result = results[0]
        for result in results[1:]:
            assert result == first_result, (
                "Singleton consistency violated under extreme load!"
            )

    def test_rapid_progress_updates(self):
        """Test rapid progress updates (stress test)"""
        tracker = ProgressTracker(total_tests=100, parallelism=20)

        def rapid_updates(test_id):
            # Perform 100 rapid updates
            for i in range(100):
                tracker.update_simple_progress(f"test_{test_id}", f"Update {i}")

        # Run 50 threads doing rapid updates
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(rapid_updates, i) for i in range(50)]
            for future in futures:
                future.result()

        # Verify state is consistent
        assert len(tracker.test_progress) == 50
