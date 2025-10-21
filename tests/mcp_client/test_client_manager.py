import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from test_mcp.mcp_client.client_manager import MCPClientManager


@pytest.mark.asyncio
class TestMCPClientManager:
    async def test_http_server_connection(self):
        """Test HTTP server connection"""
        manager = MCPClientManager()

        config = {
            "type": "url",
            "url": "http://localhost:8080/mcp",
            "authorization_token": "test-token",
        }

        with patch(
            "test_mcp.mcp_client.client_manager.streamablehttp_client"
        ) as mock_transport:
            with patch(
                "test_mcp.mcp_client.client_manager.ClientSession"
            ) as mock_session:
                # Mock transport
                mock_read_stream = AsyncMock()
                mock_write_stream = AsyncMock()
                mock_transport.return_value.__aenter__.return_value = (
                    mock_read_stream,
                    mock_write_stream,
                    None,
                )

                # Mock session
                mock_session_instance = AsyncMock()
                mock_session.return_value.__aenter__.return_value = (
                    mock_session_instance
                )
                mock_session_instance.initialize = AsyncMock()
                mock_session_instance.list_tools = AsyncMock(
                    return_value=MagicMock(tools=[])
                )
                mock_session_instance.list_resources = AsyncMock(
                    return_value=MagicMock(resources=[])
                )
                mock_session_instance.list_prompts = AsyncMock(
                    return_value=MagicMock(prompts=[])
                )

                # Test connection
                server_id = await manager.connect_server(config)

                # Verify
                assert server_id in manager.connections
                mock_transport.assert_called_once()
                mock_session_instance.initialize.assert_called_once()

    async def test_oauth_http_connection(self):
        """Test OAuth-protected HTTP server connection"""
        manager = MCPClientManager()

        config = {"type": "url", "url": "http://localhost:8080/mcp", "oauth": True}

        # Test OAuth authentication flow with connection error
        # Our new implementation tries to connect to discover metadata first
        try:
            await manager.connect_server(config)
        except RuntimeError as e:
            # Should fail with OAuth authentication error due to server not running
            assert "OAuth authentication failed" in str(e)

    async def test_tool_execution(self):
        """Test tool execution through manager"""
        manager = MCPClientManager()

        # Mock connection
        mock_connection = MagicMock()
        mock_session = AsyncMock()
        mock_connection.session = mock_session
        mock_connection._is_healthy = True
        mock_connection.server_config = {}

        # Mock tool result - needs proper async mock
        mock_result = MagicMock()
        mock_result.content = [MagicMock(type="text", text="Tool result")]
        # Use AsyncMock's return_value to properly handle awaiting
        mock_session.call_tool = AsyncMock(return_value=mock_result)

        manager.connections["test-server"] = mock_connection
        manager._connection_locks["test-server"] = asyncio.Lock()

        # Test tool execution
        result = await manager.execute_tool(
            "test-server", "test-tool", {"arg": "value"}
        )

        assert result["success"] is True
        assert len(result["content"]) == 1
        assert result["content"][0]["type"] == "text"

    async def test_tool_execution_error(self):
        """Test tool execution error handling"""
        manager = MCPClientManager()

        # Test with non-existent server
        result = await manager.execute_tool("non-existent", "test-tool", {})

        assert result["success"] is False
        assert "No connection found" in result["error"]

    async def test_resource_reading(self):
        """Test resource reading through manager"""
        manager = MCPClientManager()

        # Mock connection
        mock_connection = MagicMock()
        mock_session = AsyncMock()
        mock_connection.session = mock_session

        # Mock resource result
        mock_result = MagicMock()
        mock_result.contents = [MagicMock(type="text", text="Resource content")]
        mock_session.read_resource.return_value = mock_result

        manager.connections["test-server"] = mock_connection
        manager._connection_locks["test-server"] = asyncio.Lock()

        # Test resource reading
        result = await manager.read_resource("test-server", "test://resource")

        assert result["success"] is True
        assert result["uri"] == "test://resource"
        assert len(result["contents"]) == 1

    async def test_prompt_getting(self):
        """Test prompt getting through manager"""
        manager = MCPClientManager()

        # Mock connection
        mock_connection = MagicMock()
        mock_session = AsyncMock()
        mock_connection.session = mock_session

        # Mock prompt result
        mock_result = MagicMock()
        mock_message = MagicMock()
        mock_message.role = "user"
        mock_message.content = "Test prompt content"
        mock_result.messages = [mock_message]
        mock_session.get_prompt.return_value = mock_result

        manager.connections["test-server"] = mock_connection
        manager._connection_locks["test-server"] = asyncio.Lock()

        # Test prompt getting
        result = await manager.get_prompt(
            "test-server", "test-prompt", {"arg": "value"}
        )

        assert result["success"] is True
        assert result["prompt_name"] == "test-prompt"
        assert len(result["messages"]) == 1

    async def test_tools_for_llm(self):
        """Test getting tools formatted for LLM providers"""
        manager = MCPClientManager()

        # Mock connection
        mock_connection = MagicMock()
        mock_connection.tools = [
            {"name": "test-tool", "description": "A test tool"},
            {"name": "another-tool", "description": "Another test tool"},
        ]

        manager.connections["test-server"] = mock_connection

        # Test getting tools
        tools = await manager.get_tools_for_llm(["test-server"])

        assert len(tools) == 2
        assert tools[0]["name"] == "test-tool"
        assert tools[0]["_mcp_server_id"] == "test-server"
        assert tools[1]["name"] == "another-tool"
        assert tools[1]["_mcp_server_id"] == "test-server"

    async def test_concurrent_servers(self):
        """Test multiple server connections"""
        manager = MCPClientManager()

        # Mock multiple connections
        server_configs = [
            {"type": "url", "url": "http://server1.com/mcp", "name": "server1"},
            {"type": "url", "url": "http://server2.com/mcp", "name": "server2"},
        ]

        with patch(
            "test_mcp.mcp_client.client_manager.streamablehttp_client"
        ) as mock_transport:
            with patch(
                "test_mcp.mcp_client.client_manager.ClientSession"
            ) as mock_session:
                # Setup mocks for successful connections
                mock_transport.return_value.__aenter__.return_value = (
                    AsyncMock(),
                    AsyncMock(),
                    None,
                )
                mock_session_instance = AsyncMock()
                mock_session.return_value.__aenter__.return_value = (
                    mock_session_instance
                )
                mock_session_instance.initialize = AsyncMock()
                mock_session_instance.list_tools = AsyncMock(
                    return_value=MagicMock(tools=[])
                )
                mock_session_instance.list_resources = AsyncMock(
                    return_value=MagicMock(resources=[])
                )
                mock_session_instance.list_prompts = AsyncMock(
                    return_value=MagicMock(prompts=[])
                )

                # Connect to both servers
                server_ids = []
                for config in server_configs:
                    server_id = await manager.connect_server(config)
                    server_ids.append(server_id)

                # Verify both connections exist
                assert len(manager.connections) == 2
                assert len(server_ids) == 2

                # Test getting combined tools from both servers
                tools = await manager.get_tools_for_llm(server_ids)
                # Should work even with empty tools lists
                assert isinstance(tools, list)

    async def test_cleanup(self):
        """Test connection cleanup"""
        manager = MCPClientManager()

        # Mock a connection
        mock_context = AsyncMock()
        manager.connections["test-server"] = MagicMock()
        manager._active_contexts["test-server"] = mock_context
        manager._connection_locks["test-server"] = asyncio.Lock()

        # Test cleanup
        await manager.disconnect_server("test-server")

        # Verify cleanup
        assert "test-server" not in manager.connections
        assert "test-server" not in manager._active_contexts
        assert "test-server" not in manager._connection_locks
        mock_context.__aexit__.assert_called_once_with(None, None, None)

    async def test_disconnect_all(self):
        """Test disconnecting from all servers"""
        manager = MCPClientManager()

        # Mock multiple connections
        mock_context1 = AsyncMock()
        mock_context2 = AsyncMock()
        manager.connections = {"server1": MagicMock(), "server2": MagicMock()}
        manager._active_contexts = {"server1": mock_context1, "server2": mock_context2}
        manager._connection_locks = {
            "server1": asyncio.Lock(),
            "server2": asyncio.Lock(),
        }

        # Test disconnect all
        await manager.disconnect_all()

        # Verify all disconnected
        assert len(manager.connections) == 0
        assert len(manager._active_contexts) == 0
        assert len(manager._connection_locks) == 0
        mock_context1.__aexit__.assert_called_once_with(None, None, None)
        mock_context2.__aexit__.assert_called_once_with(None, None, None)
