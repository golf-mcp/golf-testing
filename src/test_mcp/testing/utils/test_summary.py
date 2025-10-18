"""
Test run summary utilities.

Extracted from TestExecutor to provide summary generation without single-turn testing dependency.
"""

from ..core.test_models import TestRun, TestRunSummary, ExecutionStatus


def generate_test_run_summary(test_run: TestRun) -> TestRunSummary:
    """Generate a summary of test run results"""
    # Count results by status
    completed_tests = [
        e for e in test_run.executions if e.status == ExecutionStatus.COMPLETED
    ]
    failed_tests = [e for e in test_run.executions if e.status == ExecutionStatus.FAILED]
    timeout_tests = [e for e in test_run.executions if e.status == ExecutionStatus.TIMEOUT]

    total_duration = 0.0
    if test_run.start_time and test_run.end_time:
        total_duration = (test_run.end_time - test_run.start_time).total_seconds()

    # Analyze failure patterns
    failure_patterns = []
    for execution in failed_tests + timeout_tests:
        if execution.error_message:
            failure_patterns.append(execution.error_message)

    # Count common failure types
    goal_not_achieved = len(
        [e for e in failed_tests if "goal" in (e.error_message or "").lower()]
    )
    tool_errors = len(
        [e for e in failed_tests if "tool" in (e.error_message or "").lower()]
    )

    summary = TestRunSummary(
        run_id=test_run.run_id,
        suite_name=test_run.suite.name,
        total_tests=len(test_run.executions),
        pass_rate=(
            len(completed_tests) / len(test_run.executions)
            if test_run.executions
            else 0
        ),
        duration_seconds=total_duration,
        goal_not_achieved_count=goal_not_achieved,
        tool_usage_errors_count=tool_errors,
        timeout_count=len(timeout_tests),
        agent_errors_count=len(failed_tests),
        common_failure_patterns=list(set(failure_patterns))[
            :5
        ],  # Top 5 unique patterns
    )

    return summary
