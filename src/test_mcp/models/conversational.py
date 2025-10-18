from pydantic import Field

from .base import BaseTestConfig, BaseTestSuite


class ConversationalTestConfig(BaseTestConfig):
    """Multi-turn conversation test case"""

    user_message: str = Field(..., description="Initial user message")
    success_criteria: str = Field(..., description="Natural language success criteria")
    max_turns: int | None = Field(default=10, description="Maximum conversation turns")
    context_persistence: bool = Field(
        default=True, description="Whether to maintain conversation context"
    )
    timeout_seconds: int | None = Field(
        default=300, description="Maximum time in seconds for this test to complete"
    )


class ConversationTestSuite(BaseTestSuite):
    """Conversational test suite with dialogue-specific settings"""

    # Override inherited fields with typed test cases
    test_cases: list[ConversationalTestConfig] = Field(
        default_factory=list, description="Conversational test cases to execute"
    )

    # Type-specific settings
    user_patience_level: str = Field(
        default="medium", description="User patience level (low, medium, high)"
    )
    conversation_style: str = Field(
        default="natural", description="Conversation simulation style"
    )

    def get_tests(self) -> list[ConversationalTestConfig]:
        return self.test_cases
