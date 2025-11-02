import statistics
from dataclasses import dataclass, field


@dataclass
class TestExecutionMetrics:
    """Metrics for individual test execution"""

    test_id: str
    start_time: float
    end_time: float | None = None
    turns_completed: int = 0
    api_calls_made: int = 0
    success: bool = False
    error_message: str | None = None

    @property
    def duration(self) -> float | None:
        """Calculate duration from start and end times"""
        if self.end_time is None:
            return None
        return self.end_time - self.start_time

    def __post_init__(self):
        """Validate metrics after initialization"""
        if self.end_time is not None and self.end_time < self.start_time:
            raise ValueError(
                f"end_time ({self.end_time}) cannot be before start_time ({self.start_time})"
            )
        if self.api_calls_made < 0:
            raise ValueError("api_calls_made cannot be negative")
        if self.turns_completed < 0:
            raise ValueError("turns_completed cannot be negative")


@dataclass
class SuiteExecutionMetrics:
    """Metrics for entire test suite execution"""

    suite_id: str
    start_time: float
    test_metrics: list[TestExecutionMetrics] = field(default_factory=list)
    parallelism_used: int = 1
    total_duration: float | None = None

    def get_summary_stats(self) -> dict[str, str | int | float | None]:
        """Generate summary statistics for the test suite"""
        completed_tests = [t for t in self.test_metrics if t.duration is not None]

        if not completed_tests:
            return {"status": "no_completed_tests"}

        # Duration is guaranteed to be not None for completed_tests
        durations = [t.duration for t in completed_tests]

        return {
            "total_tests": len(self.test_metrics),
            "completed_tests": len(completed_tests),
            "success_rate": len([t for t in completed_tests if t.success])
            / len(completed_tests),
            "average_duration": statistics.mean(durations),
            "median_duration": statistics.median(durations),
            "total_api_calls": sum(t.api_calls_made for t in completed_tests),
            "parallelism_efficiency": (
                len(completed_tests) / self.total_duration
                if self.total_duration and self.total_duration > 0
                else None
            ),
        }
