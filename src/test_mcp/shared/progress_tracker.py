import asyncio
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from .console_shared import get_console
from .result_models import TestStatus, TestType


@dataclass
class TestProgress:
    """Progress tracking for any test type"""

    test_id: str
    test_type: TestType
    status: TestStatus = TestStatus.QUEUED
    start_time: datetime | None = None

    # Generic progress tracking
    current_step: int = 0
    total_steps: int = 1
    step_description: str = ""

    # Type-specific details (extensible)
    details: dict[str, Any] | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if self.details is None:
            self.details = {}


class ProgressTracker:
    """Progress tracking for all test types"""

    def __init__(
        self, total_tests: int, parallelism: int, test_types: list[str] | None = None
    ):
        self.console = get_console().console
        self.total_tests = total_tests
        self.parallelism = parallelism
        self.test_types = test_types or ["conversation"]
        self.test_progress: dict[str, TestProgress] = {}

        # Use both threading and asyncio compatible synchronization
        self._thread_lock = threading.Lock()  # For synchronous calls
        self._async_lock = None  # Will be created when needed for async calls

        # Setup rich progress components
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        )

        self.overall_task = self.progress.add_task(
            f"Running {total_tests} tests (max {parallelism} parallel)",
            total=total_tests,
        )

    def _get_async_lock(self):
        """Get or create async lock for asyncio contexts with thread safety"""
        if self._async_lock is None:
            with self._thread_lock:  # Use existing thread lock for protection
                if self._async_lock is None:
                    try:
                        asyncio.get_running_loop()
                        self._async_lock = asyncio.Lock()
                    except RuntimeError:
                        # Not in async context, will use thread lock
                        pass
        return self._async_lock

    def update_test_status(
        self, test_id: str, test_type: TestType, status: TestStatus, **kwargs: Any
    ) -> None:
        """Thread-safe update of test status"""
        with self._thread_lock:
            self._update_test_status_impl(test_id, test_type, status, **kwargs)

    async def async_update_test_status(
        self, test_id: str, test_type: TestType, status: TestStatus, **kwargs: Any
    ) -> None:
        """Async-safe update of test status"""
        async_lock = self._get_async_lock()
        if async_lock is not None:
            async with async_lock:
                self._update_test_status_impl(test_id, test_type, status, **kwargs)
        else:
            # Fallback to thread lock if not in async context
            with self._thread_lock:
                self._update_test_status_impl(test_id, test_type, status, **kwargs)

    def _update_test_status_impl(
        self, test_id: str, test_type: TestType, status: TestStatus, **kwargs: Any
    ) -> None:
        """Core test status update implementation (already inside lock)"""
        if test_id not in self.test_progress:
            self.test_progress[test_id] = TestProgress(
                test_id=test_id, test_type=test_type
            )

        progress = self.test_progress[test_id]
        progress.status = status

        # Update progress fields
        for key, value in kwargs.items():
            if hasattr(progress, key):
                setattr(progress, key, value)
            elif progress.details is not None:
                progress.details[key] = value

        if status in [TestStatus.COMPLETED, TestStatus.FAILED, TestStatus.TIMEOUT]:
            self.progress.advance(self.overall_task, 1)

    def generate_status_table(self) -> Table:
        """Generate real-time status table optimized for parallel execution"""
        table = Table(title=f"Test Execution Status (Max {self.parallelism} Parallel)")
        table.add_column("Test ID", style="cyan", no_wrap=True, width=25)
        table.add_column("Status", justify="center", width=10)
        table.add_column("Progress", justify="center", width=12)
        table.add_column("Duration", justify="center", width=10)
        table.add_column("Current Activity", style="dim", width=35)

        status_icons = {
            TestStatus.QUEUED: "...",
            TestStatus.RUNNING: "🔄 RUNNING",
            TestStatus.COMPLETED: "✅ PASSED",
            TestStatus.FAILED: "❌ FAILED",
            TestStatus.TIMEOUT: "⏱️ TIMEOUT",
            TestStatus.SKIPPED: "⏭️ SKIP",
        }

        with self._thread_lock:
            # Show all currently running tests (not just first 10)
            running_tests = [
                (id, p)
                for id, p in self.test_progress.items()
                if p.status == TestStatus.RUNNING
            ]

            # Sort by start time to show earliest tests first
            running_tests.sort(key=lambda x: x[1].start_time or datetime.now())

            for test_id, progress in running_tests:
                duration = self._calculate_duration(progress)
                activity = progress.step_description or "Running conversation..."

                table.add_row(
                    test_id[:24],  # Truncate long test IDs
                    status_icons.get(progress.status, "?"),
                    f"{progress.current_step}/{progress.total_steps}",
                    f"{duration:.1f}s",
                    activity[:34]  # Truncate long activities
                )

            # Show recent completions (success and failures)
            completed_tests = [
                (id, p)
                for id, p in self.test_progress.items()
                if p.status in [TestStatus.COMPLETED, TestStatus.FAILED]
            ]

            # Sort by completion time, show most recent first
            completed_tests.sort(
                key=lambda x: x[1].details.get("end_time", datetime.now()) if x[1].details else datetime.now(),
                reverse=True
            )

            for test_id, progress in completed_tests[:5]:  # Show last 5 completed
                duration = self._calculate_duration(progress)
                status_icon = status_icons.get(progress.status, "?")
                activity = progress.error_message[:30] if progress.error_message else "Completed successfully"

                table.add_row(
                    test_id[:24],
                    status_icon,
                    "Done",
                    f"{duration:.1f}s",
                    activity
                )

        return table

    def _calculate_duration(self, progress: TestProgress) -> float:
        """Calculate test duration safely"""
        if not progress.start_time:
            return 0.0

        end_time = progress.details.get("end_time") if progress.details else None
        if end_time:
            return (end_time - progress.start_time).total_seconds()
        else:
            return (datetime.now() - progress.start_time).total_seconds()

    def update_parallel_test_progress(
        self,
        test_id: str,
        step_description: str = "",
        completed: bool = False,
        current_step: int | None = None,
        total_steps: int | None = None
    ) -> None:
        """Enhanced progress update for parallel test execution"""
        with self._thread_lock:
            current_time = datetime.now()

            # Create or update test progress
            if test_id not in self.test_progress:
                self.test_progress[test_id] = TestProgress(
                    test_id=test_id,
                    test_type=TestType.CONVERSATION,
                    status=TestStatus.RUNNING,
                    start_time=current_time,
                    current_step=current_step or 0,
                    total_steps=total_steps or 1
                )

            progress = self.test_progress[test_id]
            progress.step_description = step_description

            if current_step is not None:
                progress.current_step = current_step
            if total_steps is not None:
                progress.total_steps = total_steps

            # Update details dictionary
            if progress.details is None:
                progress.details = {}
            progress.details["last_update"] = current_time

            # Mark as completed if specified
            if completed:
                progress.status = TestStatus.COMPLETED
                progress.details["end_time"] = current_time

            # Update Rich progress display
            self._update_rich_progress()

    def add_test_type_support(
        self, test_type: str, step_names: list[str] | None = None
    ) -> None:
        """Extend progress tracker to support new test types"""
        if test_type not in self.test_types:
            self.test_types.append(test_type)

    def update_simple_progress(
        self, test_id: str, step_description: str = "", completed: bool = False
    ) -> None:
        """Thread-safe progress update - always synchronous for UI consistency"""
        with self._thread_lock:
            self._update_simple_progress_impl(test_id, step_description, completed)

    async def _async_update_simple_progress(
        self, test_id: str, step_description: str = "", completed: bool = False
    ):
        """Async version of simple progress update"""
        async with self._get_async_lock():
            self._update_simple_progress_impl(test_id, step_description, completed)

    def _update_simple_progress_impl(
        self, test_id: str, step_description: str, completed: bool
    ):
        """Core progress update implementation (thread-safe)"""
        current_time = datetime.now()

        # Update or create test progress entry using TestProgress objects
        if test_id not in self.test_progress:
            from .result_models import TestType

            self.test_progress[test_id] = TestProgress(
                test_id=test_id,
                test_type=TestType.CONVERSATION,  # Default type
                status=TestStatus.RUNNING,
                start_time=current_time,
            )

        progress = self.test_progress[test_id]
        progress.step_description = step_description
        if progress.details is None:
            progress.details = {}
        progress.details["last_update"] = current_time

        # Mark completed if specified
        if completed:
            progress.status = TestStatus.COMPLETED
            if progress.details is not None:
                progress.details["end_time"] = current_time

        # Update Rich progress bar
        self._update_rich_progress()

    def _update_rich_progress(self):
        """Update Rich progress display"""
        completed_count = len(
            [p for p in self.test_progress.values() if p.status == TestStatus.COMPLETED]
        )
        self.progress.update(self.overall_task, completed=completed_count)

    def get_simple_progress_display(
        self, suite_name: str = "", server_name: str = ""
    ) -> str:
        """Get simplified progress display for mcp-t commands"""
        with self._thread_lock:
            running_count = len(
                [
                    p
                    for p in self.test_progress.values()
                    if p.status == TestStatus.RUNNING
                ]
            )
            completed_count = len(
                [
                    p
                    for p in self.test_progress.values()
                    if p.status == TestStatus.COMPLETED
                ]
            )
            failed_count = len(
                [
                    p
                    for p in self.test_progress.values()
                    if p.status == TestStatus.FAILED
                ]
            )

            status_parts = []
            if suite_name and server_name:
                status_parts.append(
                    f"[cyan]{suite_name}[/cyan] → [cyan]{server_name}[/cyan]"
                )

            status_parts.append(
                f"Progress: {completed_count + failed_count}/{self.total_tests}"
            )

            if running_count > 0:
                # Show currently running test
                running_tests = [
                    p
                    for p in self.test_progress.values()
                    if p.status == TestStatus.RUNNING
                ]
                if running_tests:
                    current_test = running_tests[0]
                    status_parts.append(f"Current: {current_test.test_id}")
                    if current_test.step_description:
                        status_parts.append(f"({current_test.step_description})")

            return " | ".join(status_parts)
