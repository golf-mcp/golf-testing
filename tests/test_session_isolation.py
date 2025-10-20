"""Tests for provider session isolation in parallel execution"""
import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch
from src.test_mcp.providers.provider_interface import AnthropicProvider, ProviderMetrics, ProviderType


@pytest.mark.asyncio
async def test_sessions_dict_lock_protection():
    """Test provider sessions dict is protected by lock"""
    config = {"api_key": "test_key", "model": "claude-sonnet-4-20250514"}
    provider = AnthropicProvider(config)

    # Verify lock exists
    assert hasattr(provider, "_sessions_lock")
    assert isinstance(provider._sessions_lock, asyncio.Lock)


@pytest.mark.asyncio
async def test_parallel_session_creation():
    """Test multiple parallel sessions can be created safely"""
    config = {
        "api_key": "test_key",
        "model": "claude-sonnet-4-20250514",
        "mcp_servers": []
    }
    provider = AnthropicProvider(config)

    # Mock the MCP client connection
    with patch("src.test_mcp.mcp_client.client_manager.MCPClientManager") as MockMCP:
        mock_client = AsyncMock()
        MockMCP.return_value = mock_client
        mock_client.connect_server = AsyncMock(return_value="server_id")

        # Create 5 parallel sessions
        session_ids = [f"session_{i}" for i in range(5)]
        await asyncio.gather(*[
            provider.start_session(sid) for sid in session_ids
        ])

        # Verify each has isolated session
        async with provider._sessions_lock:
            assert len(provider.sessions) == 5
            for sid in session_ids:
                assert sid in provider.sessions


@pytest.mark.asyncio
async def test_parallel_session_cleanup():
    """Test parallel session cleanup doesn't interfere"""
    config = {
        "api_key": "test_key",
        "model": "claude-sonnet-4-20250514",
        "mcp_servers": []
    }
    provider = AnthropicProvider(config)

    # Add mock sessions
    session_ids = [f"session_{i}" for i in range(5)]
    for sid in session_ids:
        mock_client = Mock()
        mock_client.disconnect_server = AsyncMock()
        async with provider._sessions_lock:
            provider.sessions[sid] = {
                "created_at": 0.0,
                "mcp_client": mock_client,
                "server_ids": ["server_1"]
            }

    # Clean up all sessions in parallel
    await asyncio.gather(*[
        provider.end_session(sid) for sid in session_ids
    ])

    # Verify all cleaned up
    async with provider._sessions_lock:
        assert len(provider.sessions) == 0


@pytest.mark.asyncio
async def test_metrics_no_lost_updates():
    """Test provider metrics don't lose updates under concurrency"""
    config = {"api_key": "test_key"}
    provider = AnthropicProvider(config)

    async def increment_metrics():
        for _ in range(100):
            await provider.metrics.increment_requests()

    # Run 10 tasks incrementing concurrently
    await asyncio.gather(*[increment_metrics() for _ in range(10)])

    # Should be exactly 1000 (no lost updates)
    assert provider.metrics.requests_made == 1000


@pytest.mark.asyncio
async def test_metrics_latency_tracking():
    """Test latency tracking is thread-safe"""
    metrics = ProviderMetrics(provider=ProviderType.ANTHROPIC)

    async def add_latencies():
        for i in range(100):
            await metrics.add_latency(float(i))

    # Run 10 tasks concurrently
    await asyncio.gather(*[add_latencies() for _ in range(10)])

    # Total should be sum of 0..99 * 10 iterations
    expected_total = sum(range(100)) * 10
    assert metrics.total_latency_ms == expected_total


@pytest.mark.asyncio
async def test_metrics_error_counting():
    """Test error counting is thread-safe"""
    metrics = ProviderMetrics(provider=ProviderType.ANTHROPIC)

    async def increment_errors():
        for _ in range(50):
            await metrics.increment_errors()

    # Run 10 tasks concurrently
    await asyncio.gather(*[increment_errors() for _ in range(10)])

    # Should be exactly 500
    assert metrics.error_count == 500


@pytest.mark.asyncio
async def test_session_dict_no_runtime_error():
    """Test sessions dict doesn't raise 'dictionary changed size' error"""
    config = {
        "api_key": "test_key",
        "model": "claude-sonnet-4-20250514",
        "mcp_servers": []
    }
    provider = AnthropicProvider(config)

    # Add mock sessions
    for i in range(10):
        mock_client = Mock()
        mock_client.disconnect_server = AsyncMock()
        async with provider._sessions_lock:
            provider.sessions[f"session_{i}"] = {
                "created_at": 0.0,
                "mcp_client": mock_client,
                "server_ids": []
            }

    # Concurrently read and modify
    async def reader():
        for _ in range(50):
            async with provider._sessions_lock:
                list(provider.sessions.keys())
            await asyncio.sleep(0.001)

    async def writer():
        for i in range(10, 20):
            mock_client = Mock()
            mock_client.disconnect_server = AsyncMock()
            async with provider._sessions_lock:
                provider.sessions[f"session_{i}"] = {
                    "created_at": 0.0,
                    "mcp_client": mock_client,
                    "server_ids": []
                }
            await asyncio.sleep(0.001)

    # Should not raise RuntimeError
    await asyncio.gather(reader(), writer())
