from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .conversation_models import ConversationTurn

from ..core.test_models import TestCase
from ..utils.openai_client import OpenAIClientWrapper
from .conversation_models import (
    ConversationConfig,
    ConversationStatus,
    UserSimulatorResponse,
)


class UserSimulator:
    """AI-powered user simulator for realistic conversation testing"""

    def __init__(
        self, config: ConversationConfig | None = None, api_key: str | None = None
    ):
        self.config = config or ConversationConfig()
        self.openai_client = OpenAIClientWrapper(
            model=self.config.user_simulator_model, api_key=api_key
        )

    def _create_user_simulation_prompt(
        self,
        test_case: TestCase,
        conversation_history: list["ConversationTurn"],
        agent_response: str,
    ) -> str:
        """Create a prompt for the user simulator to generate realistic responses"""

        # Format conversation history
        history_str = ""
        if conversation_history:
            history_str = "\n".join(
                [
                    f"{turn.speaker.upper()}: {turn.message}"
                    for turn in conversation_history[-5:]  # Last 5 turns for context
                ]
            )

        # User personality based on config
        personality_traits = {
            "low": "You are impatient and want things done quickly. You provide minimal details unless specifically asked.",
            "medium": "You are a typical user - reasonably patient but want to get things done efficiently. You provide reasonable detail.",
            "high": "You are very patient and understanding. You're willing to provide detailed information and work through issues.",
        }

        detail_preferences = {
            "minimal": "You prefer short, concise responses.",
            "normal": "You provide normal amounts of detail in your responses.",
            "verbose": "You tend to be detailed and thorough in your responses.",
        }

        prompt = f"""You are simulating a realistic user interacting with an AI agent for testing purposes.

## TEST CASE CONTEXT:
**Test ID:** {test_case.test_id}
**User's Message:** {test_case.user_message}
**Success Criteria:** {test_case.success_criteria}

## USER PERSONALITY:
{personality_traits[self.config.user_patience_level]}
{detail_preferences[self.config.user_detail_preference]}

## CONVERSATION HISTORY:
{history_str if history_str else "No previous conversation"}

## AGENT'S LATEST RESPONSE:
{agent_response}

## YOUR TASK:
Analyze the agent's response and decide how to proceed. You have several options:

1. **CONTINUE** - Agent needs more information or clarification from you
2. **COMPLETE_SUCCESS** - Agent has successfully achieved the goal
3. **COMPLETE_FAILURE** - Agent has failed and cannot/will not achieve the goal
4. **STUCK** - Conversation is going in circles or agent is confused
5. **ERROR** - Something went wrong (agent error, unexpected behavior)

## DECISION RULES:
- If the agent has FULLY COMPLETED the goal AND provided the final deliverable → COMPLETE_SUCCESS
- If the agent is making progress but needs to perform additional actions (tool calls, data processing) → CONTINUE
- If the agent is asking for reasonable information you would have → CONTINUE (provide the info)
- If the agent refuses to help or errors out → COMPLETE_FAILURE
- If the agent keeps asking the same questions → STUCK
- If the agent response contains errors or doesn't make sense → ERROR

## MULTI-STEP WORKFLOW GUIDANCE:
- If agent calls tools and states intention to do more work (e.g., "Now I'll get more details...") → CONTINUE
- If agent gathers data but hasn't synthesized/formatted the final answer → CONTINUE
- Only mark COMPLETE_SUCCESS when the agent has delivered the final requested output to you
- Consider partial progress as "working toward goal" not "goal achieved"

## RESPONSE FORMAT:
Respond with a JSON object in this exact format:

```json
{{
    "response_type": "continue|complete_success|complete_failure|stuck|error",
    "user_message": "What you would say as a user (only if continuing)",
    "reasoning": "Why you made this decision",
    "confidence": 0.9,
    "completion_reason": "Brief reason if completing/stuck/error"
}}
```

## IMPORTANT:
- Stay in character as a real user trying to accomplish the goal
- Be realistic - don't provide information the user wouldn't reasonably have
- If continuing, provide helpful responses that move toward the goal
- Be decisive about when the goal is achieved or failed

Respond with ONLY the JSON object, no additional text."""

        return prompt

    def simulate_user_response(
        self,
        test_case: TestCase,
        conversation_history: list["ConversationTurn"],
        agent_response: str,
    ) -> UserSimulatorResponse:
        """Generate a realistic user response to the agent's message"""

        # Handle empty agent responses early
        if not agent_response or agent_response.strip() == "":
            return UserSimulatorResponse(
                response_type="error",
                user_message=None,
                reasoning="Agent provided empty response",
                confidence=1.0,
                completion_reason="Agent returned empty message - API error",
            )

        try:
            # Create prompt for user simulation
            prompt = self._create_user_simulation_prompt(
                test_case, conversation_history, agent_response
            )

            # Define fallback data
            fallback_data = {
                "response_type": "continue",
                "user_message": "Please continue",
                "reasoning": "Fallback parsing due to error",
                "confidence": 0.3,
                "completion_reason": None,
            }

            # Use unified OpenAI client wrapper
            messages = [
                {
                    "role": "system",
                    "content": "You are a user simulator for testing AI agents. Respond only with valid JSON as specified.",
                },
                {"role": "user", "content": prompt},
            ]

            response_data, raw_response = (
                self.openai_client.create_completion_with_json_parsing(
                    messages=messages,
                    max_tokens=500,
                    temperature=self.config.user_simulator_temperature,
                    fallback_data=fallback_data,
                )
            )

            # If we have fallback data and it was a parsing failure, try intelligent inference
            if (
                response_data == fallback_data
                and raw_response != "OpenAI completion failed"
            ):
                # Try to infer intent from raw response
                lower_response = raw_response.lower()
                if "complete" in lower_response and (
                    "success" in lower_response or "done" in lower_response
                ):
                    response_data["response_type"] = "complete_success"
                    response_data["completion_reason"] = "Goal appears to be achieved"
                elif "fail" in lower_response or "error" in lower_response:
                    response_data["response_type"] = "complete_failure"
                    response_data["completion_reason"] = "Agent failed to complete task"
                elif "stuck" in lower_response or "circle" in lower_response:
                    response_data["response_type"] = "stuck"
                    response_data["completion_reason"] = "Conversation appears stuck"

            # Create UserSimulatorResponse object
            simulator_response = UserSimulatorResponse(**response_data)
            return simulator_response

        except Exception as e:
            # Error in user simulation
            print(f"Error in user simulation: {e}")

            return UserSimulatorResponse(
                response_type="error",
                user_message=None,
                reasoning=f"User simulator error: {e!s}",
                confidence=0.0,
                completion_reason=f"Simulator system error: {e!s}",
            )

    def should_conversation_continue(
        self, simulator_response: UserSimulatorResponse
    ) -> bool:
        """Determine if the conversation should continue based on simulator response"""
        return simulator_response.response_type == "continue"

    def get_conversation_status(
        self, simulator_response: UserSimulatorResponse
    ) -> ConversationStatus:
        """Convert simulator response to conversation status"""
        status_mapping = {
            "continue": ConversationStatus.ACTIVE,
            "complete_success": ConversationStatus.GOAL_ACHIEVED,
            "complete_failure": ConversationStatus.GOAL_FAILED,
            "stuck": ConversationStatus.STUCK,
            "error": ConversationStatus.ERROR,
        }

        return status_mapping.get(
            simulator_response.response_type, ConversationStatus.ERROR
        )
