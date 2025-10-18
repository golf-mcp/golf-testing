from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from ...shared.result_models import ExecutionStatus


class TestResult(str, Enum):
    """Test evaluation result"""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


class TestCase(BaseModel):
    """Core test case model aligned with type-safe models"""

    test_id: str = Field(..., description="Unique test identifier")
    user_message: str = Field(..., description="User message for the test")
    success_criteria: str = Field(..., description="Criteria for test success")
    max_turns: int | None = Field(default=10, description="Maximum conversation turns")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Test metadata")
    server_name: str | None = Field(default=None, description="Target server name")
    timeout_seconds: int = Field(default=120, description="Test timeout in seconds")

    @classmethod
    def from_config(
        cls,
        config,
        server_name: str | None = None,
        default_test_type: str = "conversation",
    ) -> "TestCase":
        """Convert test config to TestCase with type-aware field mapping and test type detection"""
        # Initialize metadata from config or create empty dict
        metadata = getattr(config, "metadata", {}) or {}
        if not isinstance(metadata, dict):
            metadata = {}

        # Detect test type if not explicitly set
        test_type = metadata.get("test_type")
        if not test_type:
            # Infer test type from config structure - FIXED to check for compliance fields properly
            if hasattr(config, "check_categories") or hasattr(
                config, "protocol_version"
            ):
                test_type = "compliance"
            elif hasattr(config, "auth_method") or hasattr(
                config, "vulnerability_checks"
            ):
                test_type = "security"
            elif hasattr(config, "providers"):
                test_type = "multi-provider"
            else:
                test_type = default_test_type

        # Include test type in metadata
        metadata["test_type"] = test_type

        base_fields = {
            "test_id": config.test_id,
            "metadata": metadata,
            "server_name": server_name,
        }

        # Type-specific field mapping
        if hasattr(config, "user_message"):  # Conversational test
            base_fields.update(
                {
                    "user_message": config.user_message,
                    "success_criteria": config.success_criteria,
                    "max_turns": getattr(config, "max_turns", 10),
                }
            )
        else:  # Compliance/Security test - use defaults
            base_fields.update(
                {
                    "user_message": f"Execute {config.test_id}",
                    "success_criteria": "Test completes successfully",
                    "max_turns": 1,
                }
            )

        # Set timeout - default if not present
        if hasattr(config, "timeout_seconds"):
            base_fields["timeout_seconds"] = config.timeout_seconds
        else:
            base_fields["timeout_seconds"] = 120

        return cls(**base_fields)


class ToolCall(BaseModel):
    """Individual MCP tool call tracking"""

    tool_name: str
    server_name: str
    input_params: dict[str, Any]
    result: dict[str, Any] | None = None
    error: str | None = None
    execution_time_ms: float | None = None


class TestExecution(BaseModel):
    """Single test execution record"""

    execution_id: str = Field(..., description="Unique execution ID")
    test_case: TestCase
    status: ExecutionStatus = ExecutionStatus.QUEUED
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: datetime | None = None
    duration_seconds: float | None = None

    # Agent interaction
    agent_response: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)

    # Errors and issues
    error_message: str | None = None
    timeout_occurred: bool = False

    # Raw data for debugging
    raw_conversation: list[dict[str, Any]] = Field(default_factory=list)


# JudgeEvaluation moved to shared.result_models for unified model system


class TestSuite(BaseModel):
    """Collection of test cases to run"""

    suite_id: str
    name: str
    description: str
    test_cases: list[TestCase]
    created_at: datetime = Field(default_factory=datetime.now)


class TestRun(BaseModel):
    """Complete test run with all executions and results"""

    run_id: str
    suite: TestSuite
    parallelism: int = Field(default=5)
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: datetime | None = None

    # Results
    executions: list[TestExecution] = Field(default_factory=list)
    evaluations: list = Field(
        default_factory=list
    )  # Type annotation removed for compatibility

    # Summary stats
    total_tests: int = 0
    passed_tests: int = 0
    failed_tests: int = 0
    error_tests: int = 0
    pass_rate: float = 0.0


class TestRunSummary(BaseModel):
    """High-level summary of test run results"""

    run_id: str
    suite_name: str
    total_tests: int
    pass_rate: float
    duration_seconds: float

    # Issue categories
    goal_not_achieved_count: int = 0
    tool_usage_errors_count: int = 0
    timeout_count: int = 0
    agent_errors_count: int = 0

    # Most common issues
    common_failure_patterns: list[str] = Field(default_factory=list)

    timestamp: datetime = Field(default_factory=datetime.now)
