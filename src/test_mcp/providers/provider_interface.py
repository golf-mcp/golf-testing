import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ProviderType(str, Enum):
    """Supported LLM providers (simplified to core providers)"""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GEMINI = "gemini"


@dataclass
class ProviderMetrics:
    """Performance metrics for provider operations"""

    provider: ProviderType
    requests_made: int = 0
    # total_tokens removed - unreliable estimation
    total_latency_ms: float = 0
    error_count: int = 0

    @property
    def average_latency_ms(self) -> float:
        return self.total_latency_ms / max(self.requests_made, 1)

    @property
    def error_rate(self) -> float:
        return self.error_count / max(self.requests_made, 1)


class ProviderInterface(ABC):
    """Abstract interface for LLM providers with async support"""

    def __init__(self, provider_type: ProviderType, config: dict[str, str]):
        self.provider_type = provider_type
        self.config = config
        self.metrics = ProviderMetrics(provider=provider_type)

    @abstractmethod
    async def send_message(
        self,
        message: str,
        system_prompt: str | None = None,
        session_id: str | None = None,
    ) -> str:
        """Send message and get response

        Args:
            message: The message to send
            system_prompt: Optional system prompt
            session_id: Optional session ID for parallel execution safety
        """
        pass

    @abstractmethod
    async def send_message_with_tools(
        self, message: str, tools: list[dict], system_prompt: str | None = None
    ) -> tuple[str, list[dict]]:
        """Send message with tool calling capability"""
        pass

    @abstractmethod
    async def send_mcp_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send direct MCP protocol request (for compliance testing)"""
        pass

    @abstractmethod
    async def start_session(self, session_id: str) -> bool:
        """Start new session for parallel execution safety"""
        pass

    @abstractmethod
    async def end_session(self, session_id: str) -> None:
        """Clean up session"""
        pass

    def get_metrics(self) -> ProviderMetrics:
        """Get performance metrics"""
        return self.metrics


class AnthropicProvider(ProviderInterface):
    """Anthropic Claude provider implementation"""

    def __init__(self, config: dict[str, str]):
        super().__init__(ProviderType.ANTHROPIC, config)
        self.api_key = config["api_key"]
        self.model = config.get("model", "claude-sonnet-4-20250514")
        self.sessions: dict[str, Any] = {}

    async def send_message(
        self,
        message: str,
        system_prompt: str | None = None,
        session_id: str | None = None,
    ) -> str:
        """Send message using Anthropic API with session-specific MCP connections"""
        start_time = time.perf_counter()
        self.metrics.requests_made += 1

        try:
            # Use session-specific MCP client if session_id is provided
            if session_id and session_id in self.sessions:
                response = await self._anthropic_api_call_with_session(
                    message, system_prompt, session_id
                )
            else:
                # Fallback to non-session mode for backward compatibility
                response = await self._anthropic_api_call(message, system_prompt)

            # Update metrics
            latency = (time.perf_counter() - start_time) * 1000
            self.metrics.total_latency_ms += latency
            # Token tracking removed - rely on provider's actual usage metrics

            return response

        except Exception:
            self.metrics.error_count += 1
            raise

    async def send_message_with_tools(
        self, message: str, tools: list[dict], system_prompt: str | None = None
    ) -> tuple[str, list[dict]]:
        """Send message with tool calling"""
        # Implementation will reuse existing agent tool calling logic
        response = await self.send_message(message, system_prompt)
        tool_results: list[dict] = []  # Extract from existing implementation
        return response, tool_results

    async def send_mcp_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Send direct MCP protocol request for compliance testing"""
        start_time = time.perf_counter()
        self.metrics.requests_made += 1

        try:
            # Build JSON-RPC 2.0 request
            import uuid

            import httpx

            request: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": method,
            }

            if params:
                request["params"] = params

            # Send direct HTTP request to MCP server endpoint
            # This bypasses the Anthropic API for direct protocol access
            mcp_server_url: str | None = self.config.get("mcp_server_url")
            if not mcp_server_url:
                raise ValueError("Direct MCP requests require mcp_server_url in config")

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(mcp_server_url, json=request)

                if response.status_code == 200:
                    response_data: dict[str, Any] = response.json()

                    # Update metrics
                    latency = (time.perf_counter() - start_time) * 1000
                    self.metrics.total_latency_ms += latency

                    return response_data
                else:
                    raise Exception(f"MCP HTTP {response.status_code}: {response.text}")

        except Exception:
            self.metrics.error_count += 1
            raise

    async def start_session(self, session_id: str) -> bool:
        """Start isolated session with dedicated MCP connections"""
        from ..mcp_client.client_manager import MCPClientManager

        # Create a dedicated MCP client manager for this session
        # This ensures each parallel test has its own isolated connection
        mcp_client = MCPClientManager()
        server_ids = []

        # Connect to MCP servers for this session
        if "mcp_servers" in self.config:
            for server in self.config["mcp_servers"]:
                try:
                    server_id = await mcp_client.connect_server(server)
                    server_ids.append(server_id)
                except Exception as e:
                    # Clean up any connections made so far
                    for sid in server_ids:
                        try:
                            await mcp_client.disconnect_server(sid)
                        except Exception:
                            pass
                    raise RuntimeError(f"Failed to connect to server: {e}") from e

        self.sessions[session_id] = {
            "created_at": time.time(),
            "message_count": 0,
            "mcp_client": mcp_client,
            "server_ids": server_ids,
        }
        return True

    async def end_session(self, session_id: str) -> None:
        """Clean up session and disconnect MCP servers"""
        if session_id in self.sessions:
            session = self.sessions[session_id]

            # Disconnect all MCP servers for this session
            mcp_client = session.get("mcp_client")
            server_ids = session.get("server_ids", [])

            if mcp_client and server_ids:
                for server_id in server_ids:
                    try:
                        await mcp_client.disconnect_server(server_id)
                    except Exception:
                        pass  # Ignore cleanup errors

            del self.sessions[session_id]

    async def _anthropic_api_call_with_session(
        self, message: str, system_prompt: str | None, session_id: str
    ) -> str:
        """Internal API call implementation using session-specific MCP client"""
        import anthropic
        from ..mcp_client.capability_router import MCPCapabilityRouter

        # Get session-specific MCP client
        session = self.sessions[session_id]
        mcp_client = session["mcp_client"]
        server_ids = session["server_ids"]

        # Get MCP tools from the session's MCP client
        mcp_tools = []
        if server_ids:
            mcp_tools = await mcp_client.get_tools_for_llm(server_ids)

        # Create capability router for tool execution
        capability_router = MCPCapabilityRouter(mcp_client)

        # Build API parameters
        api_params = {
            "model": self.model,
            "max_tokens": 8000,
            "messages": [{"role": "user", "content": message}],
        }

        if system_prompt:
            api_params["system"] = system_prompt

        # Add MCP tools if available
        if mcp_tools:
            anthropic_tools = capability_router.format_tools_for_anthropic(mcp_tools)
            api_params["tools"] = anthropic_tools

        # Create Anthropic client
        client = anthropic.Anthropic(api_key=self.api_key)

        # Make API call
        response = client.messages.create(**api_params)

        # Extract text response
        assistant_text = ""
        for content_block in response.content:
            if hasattr(content_block, "text"):
                assistant_text += content_block.text

        # Check for tool calls and execute them
        tool_calls = capability_router.parse_anthropic_tool_calls(response)
        if tool_calls:
            # Execute tools via session's MCP client
            tool_results = await capability_router.execute_tool_calls(
                tool_calls, mcp_tools
            )

            # Create tool_result messages for continuation
            tool_result_content = []
            for original_call, result in zip(tool_calls, tool_results, strict=False):
                tool_use_id = original_call.get("call_id")
                if result.get("success"):
                    result_content = str(result.get("result", ""))
                    tool_result_content.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": result_content,
                        }
                    )
                else:
                    error_msg = result.get("error", "Unknown error")
                    tool_result_content.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": f"Error: {error_msg}",
                            "is_error": True,
                        }
                    )

            # Continue conversation with tool results
            if tool_result_content:
                api_params["messages"].append(
                    {
                        "role": "assistant",
                        "content": response.content,
                    }
                )
                api_params["messages"].append(
                    {
                        "role": "user",
                        "content": tool_result_content,
                    }
                )

                # Get final response after tool execution
                final_response = client.messages.create(**api_params)

                # Extract final text
                final_text = ""
                for content_block in final_response.content:
                    if hasattr(content_block, "text"):
                        final_text += content_block.text

                return final_text

        return assistant_text

    async def _anthropic_api_call(self, message: str, system_prompt: str | None) -> str:
        """Internal API call implementation (fallback for non-session mode)"""
        # Reuse existing ClaudeAgent implementation logic
        # This ensures compatibility while providing async interface

        # For now, we'll import and use the existing ClaudeAgent
        # In a full implementation, this would be refactored to be fully async
        from ..agent.agent import ClaudeAgent
        from ..agent.models import AgentConfig
        from ..agent.models import MCPServerConfig as AgentMCPServerConfig

        # Convert our config to AgentConfig format
        # This is a temporary bridge while we transition to the new architecture
        mcp_servers = []
        if "mcp_servers" in self.config:
            for server in self.config["mcp_servers"]:
                mcp_server = AgentMCPServerConfig(
                    url=server["url"],
                    name=server["name"],
                    authorization_token=server.get("authorization_token"),
                )
                mcp_servers.append(mcp_server)

        agent_config = AgentConfig(
            anthropic_api_key=self.api_key, mcp_servers=mcp_servers
        )

        # Create agent and execute asynchronously
        agent = ClaudeAgent(agent_config)
        agent.start_new_session()

        # Call async method directly
        response = await agent.send_message(message)
        return response
