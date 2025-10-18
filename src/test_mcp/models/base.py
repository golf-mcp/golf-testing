from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class BaseTestConfig(BaseModel):
    """Base configuration for individual tests"""

    test_id: str = Field(..., description="Unique identifier for the test")
    metadata: dict[str, Any] | None = Field(
        default=None, description="Additional test metadata"
    )


class BaseTestSuite(BaseModel):
    """Base test suite with common fields"""

    suite_id: str = Field(..., description="Unique identifier for the test suite")
    name: str = Field(..., description="Human-readable name for the test suite")
    description: str | None = Field(default=None, description="Suite description")
    suite_type: str | None = Field(
        default=None,
        description="Type of test suite (security, compliance, conversational)",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Creation timestamp"
    )
    parallelism: int = Field(default=5, description="Concurrent execution limit")

    # Direct fields - no aliases, no abstract properties
    test_cases: list[Any] = Field(
        default_factory=list, description="Test cases to execute"
    )
    auth_required: bool = Field(
        default=False, description="Whether authentication is required"
    )

    def get_test_count(self) -> int:
        """Get the number of test cases in this suite"""
        return len(self.test_cases)
