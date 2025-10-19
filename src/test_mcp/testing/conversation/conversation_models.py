from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..core.test_models import TestCase, ToolCall


class ConversationStatus(str, Enum):
    """Status of an ongoing conversation"""

    ACTIVE = "active"
    GOAL_ACHIEVED = "goal_achieved"
    GOAL_FAILED = "goal_failed"
    STUCK = "stuck"
    TIMEOUT = "timeout"
    ERROR = "error"


class ConversationTurn(BaseModel):
    """Single turn in a conversation"""

    turn_number: int
    speaker: Literal["user", "agent"]
    message: str
    tool_calls: list[ToolCall] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.now)
    duration_seconds: float | None = None


class ConversationResult(BaseModel):
    """Complete conversation result"""

    test_case: TestCase
    conversation_id: str
    turns: list[ConversationTurn] = Field(default_factory=list)

    # Completion info
    status: ConversationStatus = ConversationStatus.ACTIVE
    completion_reason: str | None = None
    goal_achieved: bool = False

    # Timing
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: datetime | None = None
    total_duration_seconds: float | None = None

    # Statistics
    total_turns: int = 0
    user_turns: int = 0
    agent_turns: int = 0
    tools_used: list[str] = Field(default_factory=list)

    # Raw data for debugging
    raw_conversation_data: list[dict[str, Any]] = Field(default_factory=list)


class UserSimulatorResponse(BaseModel):
    """Response from the user simulator"""

    response_type: Literal[
        "continue", "complete_success", "complete_failure", "stuck", "error"
    ]
    user_message: str | None = None
    reasoning: str = Field(..., description="Why the simulator made this decision")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence in the response"
    )
    completion_reason: str | None = None


class ConversationConfig(BaseModel):
    """Configuration for conversation management"""

    max_turns: int = 20
    timeout_seconds: int = 300  # 5 minutes total conversation timeout
    turn_timeout_seconds: int = 60  # Per-turn timeout
    user_simulator_model: str = "gpt-4o"
    user_simulator_temperature: float = 0.3  # Slightly creative but consistent

    # Behavioral settings
    user_patience_level: Literal["low", "medium", "high"] = "medium"
    user_detail_preference: Literal["minimal", "normal", "verbose"] = "normal"
    should_simulate_typos: bool = False
    should_simulate_corrections: bool = True
