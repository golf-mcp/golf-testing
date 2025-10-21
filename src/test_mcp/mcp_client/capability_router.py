import json
from typing import Any


class MCPCapabilityRouter:
    """
    Routes capability requests (tools, resources, prompts) from LLMs to MCP servers.
    Handles format conversion between LLM and MCP formats.
    """

    def __init__(self, mcp_client_manager):
        self.mcp_client = mcp_client_manager

    def format_tools_for_anthropic(
        self, tools: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert MCP tools to Anthropic format"""
        anthropic_tools = []
        for tool in tools:
            anthropic_tool = {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "input_schema": tool.get(
                    "inputSchema", {"type": "object", "properties": {}, "required": []}
                ),
            }
            anthropic_tools.append(anthropic_tool)
        return anthropic_tools

    def format_tools_for_openai(
        self, tools: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert MCP tools to OpenAI format"""
        openai_tools = []
        for tool in tools:
            openai_tool = {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get(
                        "inputSchema",
                        {"type": "object", "properties": {}, "required": []},
                    ),
                },
            }
            openai_tools.append(openai_tool)
        return openai_tools

    def parse_anthropic_tool_calls(self, response) -> list[dict[str, Any]]:
        """Parse tool calls from Anthropic response"""
        tool_calls = []
        for block in response.content:
            if block.type == "tool_use":
                tool_calls.append(
                    {
                        "tool_name": block.name,
                        "arguments": block.input,
                        "call_id": block.id,
                    }
                )
        return tool_calls

    def parse_openai_tool_calls(self, response) -> list[dict[str, Any]]:
        """Parse tool calls from OpenAI response"""
        tool_calls = []
        if hasattr(response, "tool_calls") and response.tool_calls:
            for tool_call in response.tool_calls:
                tool_calls.append(
                    {
                        "tool_name": tool_call.function.name,
                        "arguments": json.loads(tool_call.function.arguments),
                        "call_id": tool_call.id,
                    }
                )
        return tool_calls

    async def execute_tool_calls(
        self, tool_calls: list[dict[str, Any]], tools_metadata: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Execute tool calls via MCP client.

        Args:
            tool_calls: List of tool call requests from LLM
            tools_metadata: Original tools list with server IDs

        Returns:
            List of tool execution results
        """
        results = []

        # For single-server testing, get the first (and only) connected server
        connected_servers = list(self.mcp_client.connections.keys())
        if not connected_servers:
            return [
                {
                    "call_id": call.get("call_id"),
                    "success": False,
                    "error": "No MCP servers connected",
                }
                for call in tool_calls
            ]

        server_id = connected_servers[0]  # Use the single connected server

        for call in tool_calls:
            tool_name = call["tool_name"]

            # Execute via MCP client using the single connected server
            result = await self.mcp_client.execute_tool(
                server_id=server_id, tool_name=tool_name, arguments=call["arguments"]
            )

            results.append(
                {"call_id": call.get("call_id"), "tool_name": tool_name, **result}
            )

        return results

    async def execute_resource_reads(
        self,
        resource_requests: list[dict[str, Any]],
        resources_metadata: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Execute resource read requests via MCP client.

        Args:
            resource_requests: List of resource read requests from LLM
            resources_metadata: Original resources list with server IDs

        Returns:
            List of resource read results
        """
        results = []

        # Create lookup for resource -> server mapping
        resource_server_map = {}
        for resource in resources_metadata:
            if "_mcp_server_id" in resource:
                resource_server_map[str(resource["uri"])] = resource["_mcp_server_id"]

        for request in resource_requests:
            resource_uri = request["uri"]
            server_id = resource_server_map.get(str(resource_uri))

            if not server_id:
                results.append(
                    {
                        "uri": resource_uri,
                        "success": False,
                        "error": f"No MCP server found for resource {resource_uri}",
                    }
                )
                continue

            # Read via MCP client
            result = await self.mcp_client.read_resource(
                server_id=server_id, resource_uri=resource_uri
            )

            results.append(result)

        return results

    async def execute_prompt_gets(
        self,
        prompt_requests: list[dict[str, Any]],
        prompts_metadata: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Execute prompt get requests via MCP client.

        Args:
            prompt_requests: List of prompt get requests from LLM
            prompts_metadata: Original prompts list with server IDs

        Returns:
            List of prompt results
        """
        results = []

        # Create lookup for prompt -> server mapping
        prompt_server_map = {}
        for prompt in prompts_metadata:
            if "_mcp_server_id" in prompt:
                prompt_server_map[prompt["name"]] = prompt["_mcp_server_id"]

        for request in prompt_requests:
            prompt_name = request["name"]
            server_id = prompt_server_map.get(prompt_name)

            if not server_id:
                results.append(
                    {
                        "prompt_name": prompt_name,
                        "success": False,
                        "error": f"No MCP server found for prompt {prompt_name}",
                    }
                )
                continue

            # Get prompt via MCP client
            result = await self.mcp_client.get_prompt(
                server_id=server_id,
                prompt_name=prompt_name,
                arguments=request.get("arguments"),
            )

            results.append(result)

        return results

    def format_results_for_llm(
        self, results: list[dict[str, Any]], result_type: str, provider_type: str
    ) -> str | list[dict[str, Any]]:
        """Format results for inclusion in next LLM message"""
        formatted_results: list[str | dict[str, Any]] = []

        for result in results:
            if result_type == "tool":
                if result["success"]:
                    content = result.get("content", [])
                    text_parts = [
                        item["text"] for item in content if item.get("type") == "text"
                    ]
                    result_text = "\n".join(text_parts)
                else:
                    result_text = f"Error: {result.get('error', 'Unknown error')}"

                if provider_type == "anthropic":
                    formatted_results.append(
                        f"Tool {result['tool_name']} result:\n{result_text}"
                    )
                elif provider_type == "openai":
                    formatted_results.append(
                        {
                            "tool_call_id": result.get("call_id"),
                            "role": "tool",
                            "content": result_text,
                        }
                    )

            elif result_type == "resource":
                if result["success"]:
                    contents = result.get("contents", [])
                    text_parts = [
                        item["text"] for item in contents if item.get("type") == "text"
                    ]
                    result_text = "\n".join(text_parts)
                else:
                    result_text = f"Error: {result.get('error', 'Unknown error')}"

                if provider_type == "anthropic":
                    formatted_results.append(
                        f"Resource {result['uri']} content:\n{result_text}"
                    )
                elif provider_type == "openai":
                    formatted_results.append(
                        {
                            "role": "system",
                            "content": f"Resource content: {result_text}",
                        }
                    )

            elif result_type == "prompt":
                if result["success"]:
                    messages = result.get("messages", [])
                    result_text = "\n".join(
                        [f"{msg['role']}: {msg['content']}" for msg in messages]
                    )
                else:
                    result_text = f"Error: {result.get('error', 'Unknown error')}"

                if provider_type == "anthropic":
                    formatted_results.append(
                        f"Prompt {result['prompt_name']}:\n{result_text}"
                    )
                elif provider_type == "openai":
                    # For OpenAI prompts, add messages as dictionaries
                    messages = result.get("messages", [])
                    formatted_results.extend(messages)

        if provider_type == "anthropic":
            # For Anthropic, only join string results, filter out any dictionaries
            string_results = [
                result for result in formatted_results if isinstance(result, str)
            ]
            return "\n\n".join(string_results)
        else:
            # For OpenAI, return only dictionary results, filter out strings
            dict_results = [
                result for result in formatted_results if isinstance(result, dict)
            ]
            return dict_results
