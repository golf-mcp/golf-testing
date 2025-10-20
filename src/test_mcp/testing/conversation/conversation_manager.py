import logging
import time
import uuid
from datetime import datetime
from difflib import SequenceMatcher

from ...agent.agent import ClaudeAgent
from ...agent.config import load_agent_config
from ...agent.models import AgentConfig
from ..core.test_models import TestCase, ToolCall
from .conversation_models import (
    ConversationConfig,
    ConversationResult,
    ConversationStatus,
    ConversationTurn,
)
from .user_simulator import UserSimulator


class ConversationManager:
    """Manages multi-turn conversations between user simulator and test agent"""

    def __init__(
        self,
        config: str | AgentConfig | None = None,
        conversation_config: ConversationConfig | None = None,
        rate_limiter=None,
    ):
        """
        Initialize ConversationManager.

        Args:
            config: Either a config file path (str) or AgentConfig object.
                    If None, loads from environment.
            conversation_config: Configuration for conversation behavior.
            rate_limiter: Optional rate limiter to pass to the agent.
        """
        self.conversation_config = conversation_config or ConversationConfig()
        self.logger = logging.getLogger(__name__)
        self.user_simulator = UserSimulator(self.conversation_config)
        self.rate_limiter = rate_limiter

        # Handle different config types
        if isinstance(config, str):
            # Legacy file path support
            self.agent_config = load_agent_config(config)
        elif isinstance(config, AgentConfig):
            # Direct config object - no file I/O needed!
            self.agent_config = config
        elif config is None:
            # Load from environment
            self.agent_config = load_agent_config()

        # Enable context management for testing efficiency
        self.agent_config.context_management_enabled = True

    def _add_conversation_turn(
        self,
        conversation: ConversationResult,
        speaker: str,
        message: str,
        tool_calls: list[ToolCall] | None = None,
        duration: float | None = None,
    ) -> None:
        """Add a turn to the conversation"""
        turn = ConversationTurn(
            turn_number=len(conversation.turns) + 1,
            speaker=speaker,
            message=message,
            tool_calls=tool_calls or [],
            duration_seconds=duration,
        )

        conversation.turns.append(turn)
        conversation.total_turns += 1

        if speaker == "user":
            conversation.user_turns += 1
        else:
            conversation.agent_turns += 1

        # Track tools used
        if tool_calls:
            for tool_call in tool_calls:
                if tool_call.tool_name not in conversation.tools_used:
                    conversation.tools_used.append(tool_call.tool_name)

    def _detect_repetitive_pattern(
        self, conversation: ConversationResult, window_size: int = 3
    ) -> bool:
        """Detect if agent is stuck in a repetitive pattern"""
        if conversation.agent_turns < window_size:
            return False

        # Get last N agent messages
        agent_messages = [
            turn.message.lower()
            for turn in conversation.turns[-window_size * 2 :]
            if turn.speaker == "agent"
        ][-window_size:]

        # Check for highly similar consecutive messages
        if len(agent_messages) >= window_size:
            similarities = []
            for i in range(len(agent_messages) - 1):
                ratio = SequenceMatcher(
                    None, agent_messages[i], agent_messages[i + 1]
                ).ratio()
                similarities.append(ratio)

            # If 2+ consecutive messages are >70% similar, likely stuck
            high_similarity_count = sum(1 for s in similarities if s > 0.7)
            if high_similarity_count >= 2:
                return True

        return False

    def _detect_error_loop(
        self, conversation: ConversationResult, threshold: int = 3
    ) -> bool:
        """Detect if agent is repeatedly encountering errors"""
        recent_turns = conversation.turns[-threshold * 2 :]
        agent_turns = [turn for turn in recent_turns if turn.speaker == "agent"]

        error_keywords = ["error", "apologize", "sorry", "mistake", "try again"]
        error_count = sum(
            1
            for turn in agent_turns
            if any(keyword in turn.message.lower() for keyword in error_keywords)
        )

        return error_count >= threshold

    async def run_conversation(self, test_case: TestCase) -> ConversationResult:
        """Run a complete conversation for a test case"""

        # Initialize conversation
        conversation_id = str(uuid.uuid4())
        conversation = ConversationResult(
            test_case=test_case, conversation_id=conversation_id
        )

        # Debug output removed to prevent output pollution

        # Create fresh agent for conversation
        agent = ClaudeAgent(self.agent_config)
        # Configure rate limiter
        agent.rate_limiter = self.rate_limiter
        agent.start_new_session()

        try:
            # Start conversation with initial user message
            current_user_message = test_case.user_message
            conversation_start_time = time.time()

            for turn_number in range(self.conversation_config.max_turns):
                # Turn progress handled by progress tracker

                # Add user turn to conversation
                self._add_conversation_turn(conversation, "user", current_user_message)

                # Agent responds
                turn_start_time = time.time()

                try:
                    agent_response = await agent.send_message(current_user_message)
                    turn_duration = time.time() - turn_start_time

                    # Get tool calls directly from agent's stored results (already in ToolCall format)
                    tool_call_dicts = agent.get_recent_tool_results()
                    tool_calls = [
                        ToolCall(**call_dict) for call_dict in tool_call_dicts
                    ]

                    # Add agent turn to conversation
                    self._add_conversation_turn(
                        conversation, "agent", agent_response, tool_calls, turn_duration
                    )

                    # Store tool count before clearing results
                    tool_count = len(tool_calls)

                    # Clear tool results from agent session after extracting them
                    agent.clear_tool_results()

                    # Also enforce maximum conversation length to prevent runaway conversations
                    if turn_number >= 50:  # Hard limit beyond config max_turns
                        conversation.status = ConversationStatus.ERROR
                        conversation.completion_reason = (
                            "Conversation exceeded safety limit (50 turns)"
                        )
                        self.logger.warning(
                            "STOPPED: Conversation exceeded safety limit"
                        )
                        break

                    self.logger.info(
                        f"Agent responded ({turn_duration:.1f}s, {tool_count} tools)"
                    )

                    # Detect stuck patterns
                    if self._detect_repetitive_pattern(conversation):
                        conversation.status = ConversationStatus.STUCK
                        conversation.completion_reason = (
                            "Agent appears stuck in repetitive response pattern"
                        )
                        self.logger.warning("STUCK: Detected repetitive pattern")
                        break

                    if self._detect_error_loop(conversation):
                        conversation.status = ConversationStatus.STUCK
                        conversation.completion_reason = (
                            "Agent repeatedly encountering errors"
                        )
                        self.logger.warning("STUCK: Detected error loop")
                        break

                except Exception as e:
                    # Agent error with enhanced timeout context
                    error_str = str(e)

                    # Provide helpful context for timeout errors
                    if "execution timeout" in error_str.lower():
                        error_message = (
                            f"Tool execution timeout: {error_str}. "
                            f"This MCP server tool took too long to respond. "
                            f"You can increase 'tool_timeout' in the server configuration."
                        )
                    elif "connection timeout" in error_str.lower():
                        error_message = (
                            f"Connection timeout: {error_str}. "
                            f"Could not establish connection to MCP server. "
                            f"Check if server is running and consider increasing 'connection_timeout'."
                        )
                    else:
                        error_message = f"Agent error: {error_str}"

                    self._add_conversation_turn(
                        conversation,
                        "agent",
                        error_message,
                        [],
                        time.time() - turn_start_time,
                    )

                    conversation.status = ConversationStatus.ERROR
                    conversation.completion_reason = error_message
                    break

                # User simulator analyzes agent response
                # Analysis progress handled by progress tracker

                try:
                    simulator_response = self.user_simulator.simulate_user_response(
                        test_case, conversation.turns, agent_response
                    )

                    self.logger.info(
                        f"Simulator decision: {simulator_response.response_type} (confidence: {simulator_response.confidence:.2f})"
                    )
                    self.logger.debug(f"Reasoning: {simulator_response.reasoning}")

                    # Check if conversation should continue
                    if not self.user_simulator.should_conversation_continue(
                        simulator_response
                    ):
                        # Conversation is complete
                        conversation.status = (
                            self.user_simulator.get_conversation_status(
                                simulator_response
                            )
                        )
                        conversation.completion_reason = (
                            simulator_response.completion_reason
                        )
                        conversation.goal_achieved = (
                            conversation.status == ConversationStatus.GOAL_ACHIEVED
                        )
                        self.logger.info(
                            f"Conversation complete: {conversation.status.value}"
                        )
                        break

                    # Continue conversation with user simulator's response
                    current_user_message = (
                        simulator_response.user_message
                        or "No message from user simulator"
                    )
                    self.logger.debug(
                        f"User will respond: {current_user_message[:100]}{'...' if len(current_user_message) > 100 else ''}"
                    )

                except Exception as e:
                    # User simulator error
                    error_message = f"User simulator error: {e!s}"
                    conversation.status = ConversationStatus.ERROR
                    conversation.completion_reason = error_message
                    self.logger.error(f"❌ {error_message}")
                    break

            else:
                # Max turns reached
                conversation.status = ConversationStatus.TIMEOUT
                conversation.completion_reason = (
                    f"Reached maximum turns ({self.conversation_config.max_turns})"
                )
                self.logger.warning(
                    f"TIMEOUT: Conversation timed out after {self.conversation_config.max_turns} turns"
                )

        except Exception as e:
            # Unexpected error
            conversation.status = ConversationStatus.ERROR
            conversation.completion_reason = f"Unexpected error: {e!s}"
            self.logger.error(f"❌ Unexpected error: {e}")

        finally:
            # Finalize conversation
            conversation.end_time = datetime.now()
            conversation.total_duration_seconds = time.time() - conversation_start_time

            # Store raw conversation data
            try:
                conversation.raw_conversation_data = [
                    {
                        "role": msg.role,
                        "content": msg.content,
                        "timestamp": msg.timestamp.isoformat(),
                    }
                    for msg in agent.get_session_history()
                ]
            except Exception as e:
                self.logger.warning(f"Could not store raw conversation data: {e}")
                conversation.raw_conversation_data = []

            # Clean up agent session and MCP connections to prevent memory leak
            try:
                agent.reset_session()
                self.logger.debug("Agent session cleaned up")
            except Exception as e:
                self.logger.warning(f"Could not clean up agent session: {e}")

            # Important: Properly close MCP client connections
            try:
                await agent.cleanup()
                self.logger.debug("Agent MCP connections cleaned up")
            except Exception as e:
                self.logger.warning(f"Could not clean up agent MCP connections: {e}")

        self.logger.info(f"Conversation completed: {conversation.status.value}")
        self.logger.info(f"Duration: {conversation.total_duration_seconds:.1f}s")
        self.logger.info(
            f"Turns: {conversation.total_turns} ({conversation.user_turns} user, {conversation.agent_turns} agent)"
        )
        self.logger.info(
            f"Tools used: {', '.join(conversation.tools_used) if conversation.tools_used else 'None'}"
        )

        return conversation

    async def run_conversations_batch(
        self, test_cases: list[TestCase]
    ) -> list[ConversationResult]:
        """Run conversations for multiple test cases"""
        results = []

        for i, test_case in enumerate(test_cases, 1):
            self.logger.info(f"Running conversation {i}/{len(test_cases)}")

            try:
                conversation_result = await self.run_conversation(test_case)
                results.append(conversation_result)

            except Exception as e:
                # Create error result if conversation fails completely
                error_conversation = ConversationResult(
                    test_case=test_case,
                    conversation_id=str(uuid.uuid4()),
                    status=ConversationStatus.ERROR,
                    completion_reason=f"Conversation manager error: {e!s}",
                    end_time=datetime.now(),
                )
                results.append(error_conversation)
                self.logger.error(f"❌ Conversation failed: {e}")

        return results
