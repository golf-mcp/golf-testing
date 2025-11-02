from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# Import unified MCPServerConfig from config_manager
from ..config.config_manager import MCPServerConfig


class ResultsUploadConfig(BaseModel):
    """Configuration for uploading results to backend service"""

    enabled: bool = False
    api_url: str = Field(..., description="Backend API endpoint for uploading results")
    api_key: str | None = Field(None, description="API key for backend authentication")
    server_id: str | None = Field(
        None, description="Server ID to associate with test results on the platform"
    )
    timeout_seconds: int = Field(default=30, description="Upload timeout")
    retry_attempts: int = Field(default=3, description="Number of retry attempts")


class AgentConfig(BaseModel):
    """Main configuration for the AI agent - user configurable options only"""

    anthropic_api_key: str
    mcp_servers: list[MCPServerConfig] = []
    server_id: str | None = None
    results_upload: ResultsUploadConfig | None = None

    # Context management
    context_management_enabled: bool = True
    max_tool_uses_before_cleanup: int = 5
    keep_recent_tool_uses: int = 2

    # Fixed internal parameters (not user configurable)
    @property
    def model(self) -> str:
        """Fixed model for consistent testing"""
        return "claude-sonnet-4-20250514"

    @property
    def max_tokens(self) -> int:
        """Fixed token limit for consistent testing"""
        return 10000

    @property
    def temperature(self) -> float:
        """Fixed temperature for consistent testing"""
        return 0.1  # Low temperature for more deterministic results

    @property
    def system_prompt(self) -> str:
        """Get the default Claude system prompt"""
        from .config import get_default_system_prompt

        return get_default_system_prompt()


class ChatMessage(BaseModel):
    """Represents a chat message"""

    role: Literal["user", "assistant", "system"]
    content: str
    timestamp: datetime = Field(default_factory=datetime.now)


class MCPToolUse(BaseModel):
    """Represents an MCP tool use block"""

    type: Literal["mcp_tool_use"] = "mcp_tool_use"
    id: str
    name: str
    server_name: str
    input: dict[str, Any]


class MCPToolResult(BaseModel):
    """Represents an MCP tool result block"""

    type: Literal["mcp_tool_result"] = "mcp_tool_result"
    tool_use_id: str
    is_error: bool
    content: list[dict[str, Any]]


class ChatSession(BaseModel):
    """Represents a chat session"""

    session_id: str
    messages: list[ChatMessage] = []
    created_at: datetime = Field(default_factory=datetime.now)
    mcp_servers: list[MCPServerConfig] = []

    # NEW: Store tool results separately from conversation text
    tool_results: list[dict[str, Any]] = []

    # Message tracking
    message_count: int = 0  # Track messages sent to API
