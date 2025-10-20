from ...shared.result_models import JudgeEvaluation
from ..utils.openai_client import OpenAIClientWrapper
from .conversation_models import ConversationResult


class ConversationJudge:
    """Enhanced judge for evaluating complete multi-turn conversations"""

    def __init__(self, model: str = "gpt-5-2025-08-07", api_key: str | None = None):
        self.openai_client = OpenAIClientWrapper(model=model, api_key=api_key)

    def _create_conversation_evaluation_prompt(
        self, conversation: ConversationResult
    ) -> str:
        """Create a detailed prompt for evaluating a complete conversation"""

        # Format conversation turns
        conversation_str = ""
        for turn in conversation.turns:
            conversation_str += f"\n{turn.speaker.upper()}: {turn.message}"
            if turn.tool_calls:
                tool_names = [tc.tool_name for tc in turn.tool_calls]
                conversation_str += f"\n   [TOOLS USED: {', '.join(tool_names)}]"

        # Format tools used
        tools_used_str = (
            ", ".join(conversation.tools_used) if conversation.tools_used else "None"
        )

        prompt = f"""You are an expert judge evaluating the performance of an AI agent in a complete multi-turn conversation.

## TEST CASE DETAILS:
**Test ID:** {conversation.test_case.test_id}
**User's Message:** {conversation.test_case.user_message}
**Success Criteria:** {conversation.test_case.success_criteria}

## CONVERSATION RESULTS:
**Status:** {conversation.status.value}
**Duration:** {conversation.total_duration_seconds:.2f}s
**Total Turns:** {conversation.total_turns} ({conversation.user_turns} user, {conversation.agent_turns} agent)
**Tools Used:** {tools_used_str}
**Completion Reason:** {conversation.completion_reason or "Not specified"}

## COMPLETE CONVERSATION:
{conversation_str}

## EVALUATION INSTRUCTIONS:

You must evaluate this COMPLETE conversation and determine if the agent successfully achieved the user's goal through the multi-turn interaction. Consider:

1. **Goal Achievement:** Was the user's primary goal accomplished by the end of the conversation?
2. **Conversation Flow:** Did the agent handle the multi-turn conversation appropriately?
3. **Tool Usage:** Were the correct MCP tools used effectively?
4. **User Experience:** Was the interaction natural and helpful for the user?
5. **Error Handling:** Were any issues or clarifications handled well?

## IMPORTANT EVALUATION CRITERIA:

- **Multi-turn Context:** The agent may have asked for clarification or additional information - this is GOOD behavior if it led to goal achievement
- **Final Outcome:** Focus on whether the goal was ultimately achieved, not just the first response
- **Conversation Quality:** Consider the entire user experience, not just technical correctness
- **Realistic Expectations:** The agent should behave like a helpful assistant, asking for clarification when needed

## CRITICAL: STRICT JSON FORMAT REQUIRED

You MUST respond with EXACTLY this JSON structure. Do NOT use any other values than specified:

```json
{{
    "overall_result": "pass|fail|error",
    "confidence_score": 0.85,
    "goal_achieved": true|false,
    "tool_usage_correct": true|false,
    "error_handling_appropriate": true|false,
    "response_quality_score": 0.8,
    "conversation_flow_score": 0.9,
    "success_criteria_met": ["criterion1", "criterion2"],
    "success_criteria_failed": ["criterion3"],
    "identified_issues": ["issue1", "issue2"],
    "conversation_strengths": ["strength1", "strength2"],
    "reasoning": "Detailed explanation focusing on the complete conversation and goal achievement..."
}}
```

**STRICT RULES - FOLLOW EXACTLY:**
- **Boolean fields**: ONLY use `true` or `false` (lowercase, no quotes) - NEVER use "partially", "mostly", "somewhat", etc.
- **overall_result**: ONLY use "pass", "fail", or "error" (with quotes)
- **Numeric scores**: Use decimals between 0.0-1.0 (e.g., 0.85, not "85%" or "high")
- **Arrays**: Use proper JSON array format ["item1", "item2"]
- **No extra fields**: Do not add any fields not shown above
- **No comments**: Do not include // comments in JSON

**Scoring Guidelines:**
- **overall_result:** "pass" if goal achieved through conversation, "fail" if goal not achieved, "error" if technical failure
- **confidence_score:** How confident are you in this evaluation (0.0-1.0)
- **goal_achieved:** true if user's goal was completed, false if not (ONLY true/false)
- **tool_usage_correct:** true if tools used properly, false if not (ONLY true/false)
- **error_handling_appropriate:** true if errors handled well, false if not (ONLY true/false)
- **conversation_flow_score:** How well did the agent handle the multi-turn conversation (0.0-1.0)
- **response_quality_score:** Overall quality of agent responses throughout (0.0-1.0)
- **reasoning:** Explain your evaluation considering the full conversation

**Key Points:**
- Multi-turn conversations are EXPECTED - judge the final outcome
- Asking for clarification is GOOD if it leads to success
- Consider the user's experience throughout the entire interaction
- Technical tool usage should support the goal achievement

Respond with ONLY the JSON object, no additional text. Ensure it's valid JSON that can be parsed.
"""

        return prompt

    def evaluate_conversation(
        self, conversation: ConversationResult
    ) -> JudgeEvaluation:
        """Evaluate a complete conversation using the LLM judge"""

        try:
            # Create evaluation prompt
            prompt = self._create_conversation_evaluation_prompt(conversation)

            # Define fallback data for error cases
            fallback_data = {
                "overall_result": "error",
                "confidence_score": 0.0,
                "goal_achieved": False,
                "tool_usage_correct": False,
                "error_handling_appropriate": False,
                "response_quality_score": 0.0,
                "conversation_flow_score": 0.0,
                "success_criteria_met": [],
                "success_criteria_failed": conversation.test_case.success_criteria,
                "identified_issues": ["Judge evaluation failed - JSON parsing error"],
                "conversation_strengths": [],
                "reasoning": "Failed to parse judge response",
            }

            # Use unified OpenAI client wrapper
            messages = [
                {
                    "role": "system",
                    "content": "You are an expert judge evaluating AI agent conversations. Respond only with valid JSON.",
                },
                {"role": "user", "content": prompt},
            ]

            evaluation_data, _raw_response = self.openai_client.create_completion_with_json_parsing(
                messages=messages,
                max_tokens=50000,
                temperature=0.1,
                fallback_data=fallback_data,
            )

            # Create JudgeEvaluation object using new unified model
            # Map overall_result from old TestResult to success boolean
            success = evaluation_data["overall_result"] == "pass"

            # Calculate overall score from various metrics
            overall_score = (
                evaluation_data["confidence_score"] * 2
                + evaluation_data["response_quality_score"] * 3
                + evaluation_data["conversation_flow_score"] * 3
                + (1.0 if evaluation_data["goal_achieved"] else 0.0) * 2
            ) / 10  # Normalize to 0-10 scale

            # Create criteria scores dict
            criteria_scores = {
                "goal_achieved": 1.0 if evaluation_data["goal_achieved"] else 0.0,
                "tool_usage_correct": (
                    1.0 if evaluation_data["tool_usage_correct"] else 0.0
                ),
                "error_handling": (
                    1.0 if evaluation_data["error_handling_appropriate"] else 0.0
                ),
                "response_quality": evaluation_data["response_quality_score"],
                "conversation_flow": evaluation_data["conversation_flow_score"],
                "confidence": evaluation_data["confidence_score"],
            }

            judge_eval = JudgeEvaluation(
                overall_score=max(0.0, min(10.0, overall_score * 10)),  # Scale to 0-10
                criteria_scores=criteria_scores,
                reasoning=evaluation_data["reasoning"],
                success=success,
            )

            return judge_eval

        except Exception as e:
            # Create error evaluation if something goes wrong
            print(f"Error during conversation judge evaluation: {e}")

            return JudgeEvaluation(
                overall_score=0.0,
                criteria_scores={
                    "goal_achieved": 0.0,
                    "tool_usage_correct": 0.0,
                    "error_handling": 0.0,
                    "response_quality": 0.0,
                    "conversation_flow": 0.0,
                    "confidence": 0.0,
                },
                reasoning=f"Unable to evaluate conversation due to system error: {e!s}",
                success=False,
            )

    async def evaluate_conversations_parallel(
        self,
        conversations: list[ConversationResult],
        max_concurrency: int = 5
    ) -> list[JudgeEvaluation]:
        """Evaluate multiple conversations in parallel with controlled concurrency

        Args:
            conversations: List of conversation results to evaluate
            max_concurrency: Maximum concurrent evaluations (default: 5)

        Returns:
            List of judge evaluations in same order as input conversations
        """
        import asyncio

        # Semaphore to control concurrency
        semaphore = asyncio.Semaphore(max_concurrency)

        async def evaluate_one(conversation: ConversationResult, index: int):
            """Evaluate single conversation with concurrency control"""
            async with semaphore:
                print(
                    f"Evaluating conversation {index + 1}/{len(conversations)}: "
                    f"{conversation.test_case.test_id}"
                )

                # Run synchronous evaluation in executor to avoid blocking
                loop = asyncio.get_event_loop()
                evaluation = await loop.run_in_executor(
                    None,
                    self.evaluate_conversation,
                    conversation
                )

                # Print quick result
                result_symbol = "✅" if evaluation.success else "❌"
                result_text = "pass" if evaluation.success else "fail"
                confidence = evaluation.criteria_scores.get("confidence", 0.0)
                goal_achieved = evaluation.criteria_scores.get("goal_achieved", 0.0) > 0.5

                print(f"   {result_symbol} {result_text} (confidence: {confidence:.2f})")
                print(f"   Goal achieved: {'Yes' if goal_achieved else 'No'}")

                return evaluation

        # Execute evaluations in parallel
        tasks = [
            evaluate_one(conv, i)
            for i, conv in enumerate(conversations)
        ]

        evaluations = await asyncio.gather(*tasks)
        return list(evaluations)

    async def evaluate_conversations_batch_async(
        self,
        conversations: list[ConversationResult],
        parallel: bool = True,
        max_concurrency: int = 5
    ) -> list[JudgeEvaluation]:
        """Evaluate multiple conversations (sequential or parallel) - async version

        Args:
            conversations: List of conversation results to evaluate
            parallel: If True, use parallel evaluation (default: True)
            max_concurrency: Maximum concurrent evaluations when parallel=True

        Returns:
            List of judge evaluations in same order as input
        """
        if parallel:
            # Use parallel evaluation
            return await self.evaluate_conversations_parallel(conversations, max_concurrency)
        else:
            # Keep existing sequential implementation for backward compatibility
            evaluations = []
            for i, conversation in enumerate(conversations, 1):
                print(
                    f"Evaluating conversation {i}/{len(conversations)}: "
                    f"{conversation.test_case.test_id}"
                )

                evaluation = self.evaluate_conversation(conversation)
                evaluations.append(evaluation)

                # Print quick result
                result_symbol = "✅" if evaluation.success else "❌"
                result_text = "pass" if evaluation.success else "fail"
                confidence = evaluation.criteria_scores.get("confidence", 0.0)
                goal_achieved = evaluation.criteria_scores.get("goal_achieved", 0.0) > 0.5

                print(f"   {result_symbol} {result_text} (confidence: {confidence:.2f})")
                print(f"   Goal achieved: {'Yes' if goal_achieved else 'No'}")

            return evaluations

    def evaluate_conversations_batch(
        self,
        conversations: list[ConversationResult],
        parallel: bool = True,
        max_concurrency: int = 5
    ) -> list[JudgeEvaluation]:
        """Evaluate multiple conversations (sequential or parallel) - sync wrapper

        Args:
            conversations: List of conversation results to evaluate
            parallel: If True, use parallel evaluation (default: True)
            max_concurrency: Maximum concurrent evaluations when parallel=True

        Returns:
            List of judge evaluations in same order as input

        Note:
            This is a synchronous wrapper for backward compatibility.
            Use evaluate_conversations_batch_async() when already in async context.
        """
        if parallel:
            # Use parallel evaluation
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If event loop is already running, raise an error with helpful message
                    raise RuntimeError(
                        "Cannot use evaluate_conversations_batch() from async context. "
                        "Use evaluate_conversations_batch_async() instead."
                    )
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            return loop.run_until_complete(
                self.evaluate_conversations_parallel(conversations, max_concurrency)
            )
        else:
            # Keep existing sequential implementation for backward compatibility
            evaluations = []
            for i, conversation in enumerate(conversations, 1):
                print(
                    f"Evaluating conversation {i}/{len(conversations)}: "
                    f"{conversation.test_case.test_id}"
                )

                evaluation = self.evaluate_conversation(conversation)
                evaluations.append(evaluation)

                # Print quick result
                result_symbol = "✅" if evaluation.success else "❌"
                result_text = "pass" if evaluation.success else "fail"
                confidence = evaluation.criteria_scores.get("confidence", 0.0)
                goal_achieved = evaluation.criteria_scores.get("goal_achieved", 0.0) > 0.5

                print(f"   {result_symbol} {result_text} (confidence: {confidence:.2f})")
                print(f"   Goal achieved: {'Yes' if goal_achieved else 'No'}")

            return evaluations
