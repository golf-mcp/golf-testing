from abc import ABC
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ExecutionStatus(str, Enum):
    """Unified test status across all test types"""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class SuiteCategory(str, Enum):
    """Test type enumeration"""

    CONVERSATION = "conversation"
    TOOL = "tool"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    WORKFLOW = "workflow"


class ErrorType(str, Enum):
    """Error type enumeration"""

    TIMEOUT = "timeout"
    NETWORK = "network"
    VALIDATION = "validation"
    EXECUTION = "execution"
    CONFIGURATION = "configuration"


class BaseTestResult(BaseModel, ABC):
    """Foundation result model for all test types"""

    # Core identification
    test_id: str = Field(..., description="Unique test identifier")
    test_type: SuiteCategory = Field(..., description="Type of test")

    # Execution status
    status: ExecutionStatus = Field(..., description="Test execution status")
    success: bool = Field(..., description="Whether test passed")

    # Timing information
    start_time: datetime = Field(..., description="Test start timestamp")
    end_time: datetime = Field(..., description="Test completion timestamp")
    duration: float = Field(..., description="Total execution time in seconds")

    # Error handling
    error_message: str | None = Field(
        default=None, description="Error message if test failed"
    )
    error_type: ErrorType | None = Field(
        default=None, description="Type of error that occurred"
    )

    # Performance metrics (populated by provider interface)
    api_calls_made: int = Field(default=0, description="Number of API calls made")
    total_tokens: int = Field(default=0, description="Total tokens consumed")
    average_latency_ms: float = Field(default=0, description="Average API call latency")

    # Memory usage
    peak_memory_mb: float = Field(
        default=0, description="Peak memory usage during test"
    )

    # Provider information
    provider_used: str = Field(default="anthropic", description="LLM provider used")
    model_used: str = Field(default="", description="Specific model used")

    def calculate_duration(self) -> None:
        """Calculate duration if not set"""
        if not self.duration:
            delta = self.end_time - self.start_time
            self.duration = delta.total_seconds()


class JudgeEvaluation(BaseModel):
    """Structured judge evaluation model"""

    overall_score: float = Field(ge=0.0, le=10.0, description="Overall score 0-10")
    criteria_scores: dict[str, float] = Field(
        default_factory=dict, description="Individual criteria scores"
    )
    reasoning: str = Field(..., description="Judge reasoning")
    success: bool = Field(..., description="Whether test passed judge evaluation")


class ConversationTestResult(BaseTestResult):
    """Result model for conversation tests (extends BaseTestResult)"""

    test_type: SuiteCategory = Field(
        default=SuiteCategory.CONVERSATION, description="Test type identifier"
    )

    # Conversation-specific data
    turn_count: int = Field(default=0, description="Number of conversation turns")
    tools_used: list[str] = Field(
        default_factory=list, description="Tools called during conversation"
    )
    conversation_data: dict[str, Any] = Field(
        default_factory=dict, description="Full conversation history"
    )

    # Judge evaluation (structured model instead of dict)
    judge_evaluation: JudgeEvaluation | None = Field(
        default=None, description="LLM judge evaluation"
    )


class BaseTestSuiteResult(BaseModel):
    """Foundation result model for test suite execution"""

    suite_id: str = Field(..., description="Test suite identifier")
    suite_name: str = Field(..., description="Human-readable suite name")

    # Execution summary
    total_tests: int = Field(..., description="Total number of tests")
    completed_tests: int = Field(default=0, description="Number of completed tests")
    successful_tests: int = Field(default=0, description="Number of successful tests")
    failed_tests: int = Field(default=0, description="Number of failed tests")
    skipped_tests: int = Field(default=0, description="Number of skipped tests")

    # Timing
    start_time: datetime = Field(..., description="Suite start time")
    end_time: datetime = Field(..., description="Suite completion time")
    total_duration: float = Field(..., description="Total suite duration in seconds")

    # Configuration used
    parallelism_used: int = Field(default=1, description="Parallelism level used")
    provider_used: str = Field(default="anthropic", description="Primary provider used")

    # Individual test results (typed as Union to support all test types)
    test_results: list[BaseTestResult] = Field(
        default_factory=list, description="Individual test results"
    )

    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.completed_tests == 0:
            return 0.0
        return self.successful_tests / self.completed_tests

    @property
    def average_test_duration(self) -> float:
        """Calculate average test duration"""
        completed_results = [r for r in self.test_results if r.duration]
        if not completed_results:
            return 0.0
        return sum(r.duration for r in completed_results) / len(completed_results)
