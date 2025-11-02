"""Tests for performance monitoring utilities"""

import pytest
import time

from src.test_mcp.utils.performance_monitor import (
    TestExecutionMetrics,
    SuiteExecutionMetrics,
)


class TestTestExecutionMetrics:
    """Test TestExecutionMetrics dataclass"""

    def test_basic_creation(self):
        """Test creating a basic metrics object"""
        metrics = TestExecutionMetrics(
            test_id="test-1",
            start_time=100.0,
        )
        assert metrics.test_id == "test-1"
        assert metrics.start_time == 100.0
        assert metrics.end_time is None
        assert metrics.turns_completed == 0
        assert metrics.api_calls_made == 0
        assert metrics.success is False
        assert metrics.error_message is None

    def test_creation_with_all_fields(self):
        """Test creating metrics with all fields populated"""
        metrics = TestExecutionMetrics(
            test_id="test-2",
            start_time=100.0,
            end_time=150.0,
            turns_completed=5,
            api_calls_made=10,
            success=True,
            error_message="Error occurred",
        )
        assert metrics.test_id == "test-2"
        assert metrics.start_time == 100.0
        assert metrics.end_time == 150.0
        assert metrics.turns_completed == 5
        assert metrics.api_calls_made == 10
        assert metrics.success is True
        assert metrics.error_message == "Error occurred"

    def test_duration_calculation(self):
        """Test duration calculation from start and end times"""
        metrics = TestExecutionMetrics(
            test_id="test-3",
            start_time=100.0,
            end_time=150.0,
        )
        assert metrics.duration == 50.0

    def test_duration_none_when_not_ended(self):
        """Test that duration is None when end_time is not set"""
        metrics = TestExecutionMetrics(
            test_id="test-4",
            start_time=100.0,
        )
        assert metrics.duration is None

    def test_duration_zero_for_instant_completion(self):
        """Test duration can be zero for instant completion"""
        metrics = TestExecutionMetrics(
            test_id="test-5",
            start_time=100.0,
            end_time=100.0,
        )
        assert metrics.duration == 0.0

    def test_invalid_end_time_raises_error(self):
        """Test that end_time before start_time raises ValueError"""
        with pytest.raises(ValueError, match="end_time.*cannot be before start_time"):
            TestExecutionMetrics(
                test_id="test-6",
                start_time=100.0,
                end_time=50.0,
            )

    def test_negative_api_calls_raises_error(self):
        """Test that negative api_calls_made raises ValueError"""
        with pytest.raises(ValueError, match="api_calls_made cannot be negative"):
            TestExecutionMetrics(
                test_id="test-7",
                start_time=100.0,
                api_calls_made=-1,
            )

    def test_negative_turns_raises_error(self):
        """Test that negative turns_completed raises ValueError"""
        with pytest.raises(ValueError, match="turns_completed cannot be negative"):
            TestExecutionMetrics(
                test_id="test-8",
                start_time=100.0,
                turns_completed=-5,
            )

    def test_realistic_timing(self):
        """Test with realistic timing values"""
        start = time.time()
        time.sleep(0.01)  # Small delay
        end = time.time()

        metrics = TestExecutionMetrics(
            test_id="test-9",
            start_time=start,
            end_time=end,
        )
        assert metrics.duration is not None
        assert metrics.duration > 0.01
        assert metrics.duration < 1.0  # Should complete quickly


class TestSuiteExecutionMetrics:
    """Test SuiteExecutionMetrics dataclass"""

    def test_basic_creation(self):
        """Test creating a basic suite metrics object"""
        suite = SuiteExecutionMetrics(
            suite_id="suite-1",
            start_time=100.0,
        )
        assert suite.suite_id == "suite-1"
        assert suite.start_time == 100.0
        assert suite.test_metrics == []
        assert suite.parallelism_used == 1
        assert suite.total_duration is None

    def test_creation_with_tests(self):
        """Test creating suite with test metrics"""
        test1 = TestExecutionMetrics(
            test_id="test-1", start_time=100.0, end_time=110.0, success=True
        )
        test2 = TestExecutionMetrics(
            test_id="test-2", start_time=105.0, end_time=115.0, success=True
        )

        suite = SuiteExecutionMetrics(
            suite_id="suite-2",
            start_time=100.0,
            test_metrics=[test1, test2],
            parallelism_used=2,
            total_duration=15.0,
        )
        assert len(suite.test_metrics) == 2
        assert suite.parallelism_used == 2
        assert suite.total_duration == 15.0

    def test_summary_stats_empty_suite(self):
        """Test summary stats for suite with no completed tests"""
        suite = SuiteExecutionMetrics(suite_id="suite-3", start_time=100.0)
        stats = suite.get_summary_stats()
        assert stats == {"status": "no_completed_tests"}

    def test_summary_stats_with_incomplete_tests(self):
        """Test summary stats when tests haven't ended"""
        test1 = TestExecutionMetrics(test_id="test-1", start_time=100.0)

        suite = SuiteExecutionMetrics(
            suite_id="suite-4", start_time=100.0, test_metrics=[test1]
        )
        stats = suite.get_summary_stats()
        assert stats == {"status": "no_completed_tests"}

    def test_summary_stats_single_successful_test(self):
        """Test summary stats with one successful test"""
        test1 = TestExecutionMetrics(
            test_id="test-1",
            start_time=100.0,
            end_time=120.0,
            api_calls_made=5,
            success=True,
        )

        suite = SuiteExecutionMetrics(
            suite_id="suite-5",
            start_time=100.0,
            test_metrics=[test1],
            total_duration=20.0,
        )
        stats = suite.get_summary_stats()

        assert stats["total_tests"] == 1
        assert stats["completed_tests"] == 1
        assert stats["success_rate"] == 1.0
        assert stats["average_duration"] == 20.0
        assert stats["median_duration"] == 20.0
        assert stats["total_api_calls"] == 5
        assert stats["parallelism_efficiency"] == 1 / 20.0

    def test_summary_stats_multiple_tests(self):
        """Test summary stats with multiple tests"""
        test1 = TestExecutionMetrics(
            test_id="test-1",
            start_time=100.0,
            end_time=110.0,
            api_calls_made=3,
            success=True,
        )
        test2 = TestExecutionMetrics(
            test_id="test-2",
            start_time=105.0,
            end_time=125.0,
            api_calls_made=7,
            success=False,
        )
        test3 = TestExecutionMetrics(
            test_id="test-3",
            start_time=110.0,
            end_time=140.0,
            api_calls_made=5,
            success=True,
        )

        suite = SuiteExecutionMetrics(
            suite_id="suite-6",
            start_time=100.0,
            test_metrics=[test1, test2, test3],
            parallelism_used=2,
            total_duration=40.0,
        )
        stats = suite.get_summary_stats()

        assert stats["total_tests"] == 3
        assert stats["completed_tests"] == 3
        assert stats["success_rate"] == 2.0 / 3.0  # 2 out of 3 successful
        assert stats["average_duration"] == (10.0 + 20.0 + 30.0) / 3.0
        assert stats["median_duration"] == 20.0
        assert stats["total_api_calls"] == 15
        assert stats["parallelism_efficiency"] == 3 / 40.0

    def test_summary_stats_mixed_completion(self):
        """Test summary stats with mix of completed and incomplete tests"""
        test1 = TestExecutionMetrics(
            test_id="test-1",
            start_time=100.0,
            end_time=110.0,
            success=True,
        )
        test2 = TestExecutionMetrics(
            test_id="test-2",
            start_time=105.0,
        )  # Not completed

        suite = SuiteExecutionMetrics(
            suite_id="suite-7",
            start_time=100.0,
            test_metrics=[test1, test2],
        )
        stats = suite.get_summary_stats()

        assert stats["total_tests"] == 2
        assert stats["completed_tests"] == 1
        assert stats["success_rate"] == 1.0

    def test_summary_stats_zero_total_duration(self):
        """Test parallelism efficiency when total_duration is zero"""
        test1 = TestExecutionMetrics(
            test_id="test-1", start_time=100.0, end_time=110.0, success=True
        )

        suite = SuiteExecutionMetrics(
            suite_id="suite-8",
            start_time=100.0,
            test_metrics=[test1],
            total_duration=0.0,
        )
        stats = suite.get_summary_stats()

        assert stats["parallelism_efficiency"] is None

    def test_summary_stats_none_total_duration(self):
        """Test parallelism efficiency when total_duration is None"""
        test1 = TestExecutionMetrics(
            test_id="test-1", start_time=100.0, end_time=110.0, success=True
        )

        suite = SuiteExecutionMetrics(
            suite_id="suite-9", start_time=100.0, test_metrics=[test1]
        )
        stats = suite.get_summary_stats()

        assert stats["parallelism_efficiency"] is None

    def test_summary_stats_all_failed_tests(self):
        """Test summary stats when all tests failed"""
        test1 = TestExecutionMetrics(
            test_id="test-1", start_time=100.0, end_time=110.0, success=False
        )
        test2 = TestExecutionMetrics(
            test_id="test-2", start_time=105.0, end_time=115.0, success=False
        )

        suite = SuiteExecutionMetrics(
            suite_id="suite-10",
            start_time=100.0,
            test_metrics=[test1, test2],
        )
        stats = suite.get_summary_stats()

        assert stats["success_rate"] == 0.0

    def test_add_test_metrics_dynamically(self):
        """Test adding test metrics to suite after creation"""
        suite = SuiteExecutionMetrics(suite_id="suite-11", start_time=100.0)

        # Add tests dynamically
        suite.test_metrics.append(
            TestExecutionMetrics(
                test_id="test-1", start_time=100.0, end_time=110.0, success=True
            )
        )
        suite.test_metrics.append(
            TestExecutionMetrics(
                test_id="test-2", start_time=105.0, end_time=115.0, success=True
            )
        )

        stats = suite.get_summary_stats()
        assert stats["total_tests"] == 2
        assert stats["completed_tests"] == 2

