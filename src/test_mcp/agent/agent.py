import asyncio
import json
import re
import time
import uuid
from typing import Any, Literal

import anthropic
from anthropic import APIStatusError, RateLimitError

from ..mcp_client.capability_router import MCPCapabilityRouter
from ..mcp_client.client_manager import MCPClientManager
from ..testing.core.test_models import ToolCall
from .models import (
    AgentConfig,
    ChatMessage,
    ChatSession,
)


class ClaudeAgent:
    """AI Agent that integrates with Anthropic's API and supports MCP servers"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.client = anthropic.Anthropic(api_key=config.anthropic_api_key)
        self.current_session: ChatSession | None = None
        self.rate_limiter = None  # Initialize rate_limiter attribute

        # Initialize MCP client manager
        self.mcp_client = MCPClientManager()
        self.capability_router = MCPCapabilityRouter(self.mcp_client)
        self.server_ids: list[str] = []
        self.mcp_tools: list[dict[str, Any]] = []
        self.mcp_resources: list[dict[str, Any]] = []
        self.mcp_prompts: list[dict[str, Any]] = []

    async def initialize(self):
        """Connect to MCP servers"""
        if not self.config.mcp_servers:
            return

        # Connect to each MCP server
        for server_config in self.config.mcp_servers:
            try:
                server_dict = server_config.model_dump()
                server_id = await self.mcp_client.connect_server(server_dict)
                self.server_ids.append(server_id)
            except Exception as e:
                print(f"Failed to connect to server {server_config.name}: {e}")

        # Get all capabilities from connected servers
        if self.server_ids:
            self.mcp_tools = await self.mcp_client.get_tools_for_llm(self.server_ids)
            self.mcp_resources = await self.mcp_client.get_resources_for_llm(
                self.server_ids
            )
            self.mcp_prompts = await self.mcp_client.get_prompts_for_llm(
                self.server_ids
            )

    def start_new_session(self) -> ChatSession:
        """Start a new chat session"""
        session_id = str(uuid.uuid4())
        self.current_session = ChatSession(
            session_id=session_id,
            mcp_servers=self.config.mcp_servers,
        )
        return self.current_session

    def add_message(self, role: Literal["user", "assistant", "system"], content: str) -> None:
        """Add a message to the current session"""
        if not self.current_session:
            self.current_session = self.start_new_session()

        message = ChatMessage(role=role, content=content)
        self.current_session.messages.append(message)

    def _prepare_messages(self) -> list[dict[str, str]]:
        """Prepare messages for API call"""
        if not self.current_session:
            return []

        return [
            {"role": msg.role, "content": msg.content}
            for msg in self.current_session.messages
            if msg.role != "system"  # System message handled separately
        ]

    def _process_response_content(
        self, content: list[Any]
    ) -> tuple[str, list[dict[str, Any]]]:
        """Process response content and handle MCP tool calls

        Returns:
            tuple: (clean_message, tool_results)
        """
        tool_results: list[dict[str, Any]] = []

        # Use list comprehension to extract text blocks
        claude_content = [
            block.text
            for block in content
            if block.type == "text"
        ]

        # Return clean message without embedded tool results
        clean_message = "".join(claude_content)

        return clean_message, tool_results

    def _prepare_api_call(self, user_message: str) -> dict[str, Any]:
        """Prepare API call parameters"""
        # Add user message to local session
        self.add_message("user", user_message)

        # Prepare API parameters with prompt caching for efficiency
        api_params = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "system": [
                {
                    "type": "text",
                    "text": self.config.system_prompt,
                    "cache_control": {"type": "ephemeral"},  # Cache system prompt
                }
            ],
        }

        # Always send full conversation (Anthropic API is stateless)
        api_params["messages"] = self._prepare_messages()

        # Context management not supported by standard Anthropic API
        # Using prompt caching and conversation management instead

        return api_params

    def _handle_api_error(self, error: Exception) -> str:
        """Common error handling for API calls"""
        error_message = f"Error communicating with Claude: {error!s}"
        self.add_message("assistant", error_message)
        return error_message

    def _should_retry_error(self, error: Exception) -> bool:
        """Determine if an error should be retried"""

        # Handle Anthropic-specific exceptions (most reliable)
        if isinstance(error, (RateLimitError, APIStatusError)):
            if isinstance(error, RateLimitError):
                return True
            if error.status_code in (429, 529):  # Rate limit and overloaded
                return True

        # String-based detection for other providers and edge cases
        error_str = str(error).lower()
        retryable_patterns = [
            # Rate limiting
            "429",
            "529",
            "rate_limit_error",
            "overloaded",
            # Server errors
            "502",
            "503",
            "504",
            # Connection issues
            "timeout",
            "connection error",
            "server error",
        ]

        return any(pattern in error_str for pattern in retryable_patterns)

    async def _make_api_call_with_retry(self, api_params: dict) -> Any:
        """Make API call with retry logic for transient errors"""
        max_retries = 3
        base_delay = 1.0  # Start with 1 second

        for attempt in range(max_retries + 1):
            correlation_id = None
            try:
                # Acquire rate limiting slot before making API call
                if self.rate_limiter:
                    correlation_id = await self.rate_limiter.acquire_request_slot(
                        "anthropic"
                    )

                # Make API call using regular client (no beta, no MCP servers)
                response = self.client.messages.create(**api_params)

                # Record actual token usage if rate limiter is configured
                if self.rate_limiter and response.usage and correlation_id:
                    total_tokens = (
                        response.usage.input_tokens + response.usage.output_tokens
                    )
                    self.rate_limiter.record_token_usage(correlation_id, total_tokens)

                return response

            except Exception as e:
                # Clean up pending request on error
                if self.rate_limiter and correlation_id:
                    self.rate_limiter.cleanup_pending_request(correlation_id)

                # Check if this is the last attempt
                if attempt == max_retries:
                    raise e

                # Check if we should retry this error
                if not self._should_retry_error(e):
                    raise e

                # Calculate delay with exponential backoff + jitter
                delay = base_delay * (2**attempt) + (time.time() % 1)  # Add jitter

                print(
                    f"   Warning: API error (attempt {attempt + 1}/{max_retries + 1}): {e!s}"
                )
                print(f"   Retrying in {delay:.1f}s...")

                await asyncio.sleep(delay)

        # This shouldn't be reached, but just in case
        raise Exception("Max retries exceeded")

    async def send_message(self, user_message: str) -> str:
        """Send message with MCP tool support via separate client"""

        # Initialize if needed
        if not self.server_ids and self.config.mcp_servers:
            await self.initialize()

        # Prepare API parameters WITHOUT mcp_servers
        api_params = self._prepare_api_call(user_message)

        # Add tools if available
        if self.mcp_tools:
            # Convert MCP tools to Anthropic format
            anthropic_tools = self.capability_router.format_tools_for_anthropic(
                self.mcp_tools
            )
            api_params["tools"] = anthropic_tools

        # Add resources and prompts to system message if available
        if self.mcp_resources or self.mcp_prompts:
            capabilities_info = []
            if self.mcp_resources:
                resource_list = ", ".join(
                    [str(r.get("uri", "")) for r in self.mcp_resources]
                )
                capabilities_info.append(f"Available MCP resources: {resource_list}")
            if self.mcp_prompts:
                prompt_list = ", ".join([str(p["name"]) for p in self.mcp_prompts])
                capabilities_info.append(f"Available MCP prompts: {prompt_list}")

            # Enhance system prompt with available capabilities
            if capabilities_info:
                enhanced_system = (
                    api_params.get("system", "") + "\n\n" + "\n".join(capabilities_info)
                )
                api_params["system"] = enhanced_system

        try:
            # Call Anthropic API (regular call, no beta, no mcp_servers)
            response = await self._make_api_call_with_retry(api_params)

            # Process response

            # Extract text response
            assistant_text = self._extract_text_from_response(response)
            full_response = assistant_text

            # Check for tool calls in response
            tool_calls = self.capability_router.parse_anthropic_tool_calls(response)

            if tool_calls:
                # Execute tools via MCP client
                tool_results = await self.capability_router.execute_tool_calls(
                    tool_calls, self.mcp_tools
                )

                # Create ToolCall objects directly from our execution
                server_name = (
                    self.config.mcp_servers[0].name
                    if self.config.mcp_servers
                    else "unknown"
                )

                tool_call_objects = []
                for _i, (original_call, result) in enumerate(
                    zip(tool_calls, tool_results, strict=False)
                ):
                    tool_call_obj = ToolCall(
                        tool_name=original_call["tool_name"],
                        server_name=server_name,
                        input_params=original_call.get("arguments", {}),
                        result=(
                            self._extract_tool_result_content(result)
                            if result.get("success")
                            else None
                        ),
                        error=(
                            result.get("error") if not result.get("success") else None
                        ),
                    )
                    tool_call_objects.append(tool_call_obj)

                # Store the ToolCall objects directly
                if self.current_session:
                    # Convert to dict format for storage
                    tool_dicts = [obj.model_dump() for obj in tool_call_objects]
                    self.current_session.tool_results.extend(tool_dicts)

                # Create tool_result messages and continue conversation with Claude

                # Create tool_result content for each tool call
                tool_result_content = []
                for original_call, result in zip(
                    tool_calls, tool_results, strict=False
                ):
                    tool_use_id = original_call.get("call_id")  # Get the tool call ID
                    if result.get("success"):
                        # Extract the actual result content using the extraction method
                        result_content = self._extract_tool_result_content(result)
                        if (
                            isinstance(result_content, dict)
                            and "text" in result_content
                        ):
                            content = result_content["text"]
                        else:
                            content = str(result_content)

                        tool_result_content.append(
                            {
                                "type": "tool_result",
                                "tool_use_id": tool_use_id,
                                "content": content,
                            }
                        )
                    else:
                        # Handle tool errors
                        error_content = result.get("error", "Tool execution failed")
                        tool_result_content.append(
                            {
                                "type": "tool_result",
                                "tool_use_id": tool_use_id,
                                "content": f"Error: {error_content}",
                                "is_error": True,
                            }
                        )

                if tool_result_content:
                    # Continue conversation with Claude using tool results

                    # Create continued conversation messages
                    continued_messages = self._prepare_messages()
                    continued_messages.append(
                        {
                            "role": "assistant",
                            "content": response.content if isinstance(response.content, str) else [{"type": "text", "text": str(response.content)}],  # The original response with tool calls
                        }
                    )
                    continued_messages.append(
                        {"role": "user", "content": tool_result_content}
                    )

                    # Make follow-up API call for Claude to process tool results
                    continued_api_params = {
                        "model": self.config.model,
                        "max_tokens": self.config.max_tokens,
                        "messages": continued_messages,
                        "tools": (
                            self.capability_router.format_tools_for_anthropic(
                                self.mcp_tools
                            )
                            if self.mcp_tools
                            else None
                        ),
                    }

                    continued_response = await self._make_api_call_with_retry(
                        continued_api_params
                    )

                    # Use the continued response as our final response
                    full_response = self._extract_text_from_response(continued_response)
                    if not full_response or full_response.strip() == "":
                        full_response = "I've completed the tool execution but encountered an issue formulating a response."
                else:
                    pass

            # Parse for resource/prompt requests in final response
            resource_requests = self._parse_resource_requests(full_response)
            if resource_requests:
                resource_results = await self.capability_router.execute_resource_reads(
                    resource_requests, self.mcp_resources
                )
                formatted_resources = self.capability_router.format_results_for_llm(
                    resource_results, "resource", "anthropic"
                )
                full_response += f"\n\n{formatted_resources}"

            prompt_requests = self._parse_prompt_requests(full_response)
            if prompt_requests:
                prompt_results = await self.capability_router.execute_prompt_gets(
                    prompt_requests, self.mcp_prompts
                )
                formatted_prompts = self.capability_router.format_results_for_llm(
                    prompt_results, "prompt", "anthropic"
                )
                full_response += f"\n\n{formatted_prompts}"

            # Add to session
            self.add_message("assistant", full_response)

            return full_response

        except Exception as e:
            return self._handle_api_error(e)

    def _extract_text_from_response(self, response) -> str:
        """Extract text content from Anthropic response"""
        text_parts = [
            block.text
            for block in response.content
            if block.type == "text"
        ]

        result = "".join(text_parts).strip()

        if not result:
            has_tool_use = any(block.type == "tool_use" for block in response.content)
            if has_tool_use:
                return "[Processing tools...]"
            else:
                return "I apologize, I encountered an issue generating a response."

        return result

    def _extract_tool_result_content(
        self, result: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Extract and format tool result content as a dictionary"""
        if not result or not result.get("content"):
            return None

        content = result["content"]

        # Handle list format content (MCP SDK format)
        if isinstance(content, list):
            # Extract text from content blocks
            text_parts = [
                item.get("text", "")
                for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            ]

            if text_parts:
                return {"text": "\n".join(text_parts)}
            else:
                # Return structured content as-is if no text found
                return {"content": content}

        # Handle other formats
        return {"content": content}

    def _parse_resource_requests(self, text: str) -> list[dict[str, Any]]:
        """Parse resource read requests from assistant text"""
        # Example pattern: "[[read:resource_uri]]"
        pattern = r"\[\[read:(.*?)\]\]"
        matches = re.findall(pattern, text)
        return [{"uri": uri} for uri in matches]

    def _parse_prompt_requests(self, text: str) -> list[dict[str, Any]]:
        """Parse prompt get requests from assistant text"""
        prompt_requests = []
        # Example pattern: "[[prompt:prompt_name|args]]"
        pattern = r"\[\[prompt:(.*?)(?:\|(.*?))?\]\]"
        matches = re.findall(pattern, text)
        for name, args_str in matches:
            request = {"name": name}
            if args_str:
                try:
                    request["arguments"] = json.loads(args_str)
                except json.JSONDecodeError:
                    pass
            prompt_requests.append(request)
        return prompt_requests

    async def cleanup(self):
        """Clean up MCP connections in task-safe manner"""
        try:
            # Try graceful cleanup first
            await self.mcp_client.disconnect_all()
        except RuntimeError as e:
            if "cancel scope" in str(e) or "different task" in str(e):
                # Handle AnyIO task context mismatch - use forced cleanup
                self._force_cleanup_connections()
            else:
                raise

    def _force_cleanup_connections(self):
        """Force cleanup without awaiting AsyncExitStack.aclose()"""
        # Use the client manager's force cleanup method
        self.mcp_client.force_disconnect_all()
        self.server_ids.clear()
        self.mcp_tools.clear()
        self.mcp_resources.clear()
        self.mcp_prompts.clear()

    def get_session_history(self) -> list[ChatMessage]:
        """Get current session message history"""
        if not self.current_session:
            return []
        return self.current_session.messages

    def get_recent_tool_results(self) -> list[dict[str, Any]]:
        """Get tool results from the current session"""
        if not self.current_session:
            return []
        return self.current_session.tool_results

    def clear_tool_results(self) -> None:
        """Clear stored tool results from the current session"""
        if self.current_session:
            self.current_session.tool_results = []
            # Also clear stored tool calls
            if hasattr(self.current_session, "tool_calls"):
                self.current_session.tool_calls = []

    def reset_session(self) -> None:
        """Reset session state"""
        if self.current_session:
            # Clear conversation state
            self.current_session.messages = []
            self.current_session.tool_results = []
            self.current_session.message_count = 0

    def get_session_message_count(self) -> int:
        """Get the current number of messages in the session"""
        return len(self.current_session.messages) if self.current_session else 0
