"""Tests for async token storage race conditions"""
import asyncio
import pytest
from src.test_mcp.mcp_client.client_manager import SharedTokenStorage


@pytest.mark.asyncio
async def test_concurrent_token_access():
    """Test concurrent token access doesn't deadlock"""
    storage = await SharedTokenStorage.get_instance("http://test", "session1")

    async def access_tokens():
        for _ in range(100):
            await storage.set_tokens({"access_token": "test"})
            tokens = await storage.get_tokens()
            assert tokens is not None

    # Run 10 tasks concurrently
    await asyncio.gather(*[access_tokens() for _ in range(10)])


@pytest.mark.asyncio
async def test_session_isolation():
    """Test sessions get isolated token storage"""
    storage1 = await SharedTokenStorage.get_instance("http://server", "session1")
    storage2 = await SharedTokenStorage.get_instance("http://server", "session2")

    await storage1.set_tokens({"access_token": "token1"})
    await storage2.set_tokens({"access_token": "token2"})

    token1 = await storage1.get_tokens()
    token2 = await storage2.get_tokens()

    assert token1["access_token"] == "token1"
    assert token2["access_token"] == "token2"


@pytest.mark.asyncio
async def test_no_deadlock_under_load():
    """Stress test: 100 concurrent token operations"""
    storage = await SharedTokenStorage.get_instance("http://test", "stress")

    async def rapid_operations():
        for i in range(50):
            await storage.set_tokens({"token": f"token{i}"})
            await storage.get_tokens()

    # Should complete without deadlock
    await asyncio.wait_for(
        asyncio.gather(*[rapid_operations() for _ in range(100)]),
        timeout=30.0
    )


@pytest.mark.asyncio
async def test_clear_all_async_no_toctou():
    """Test clear_all_async has no TOCTOU race"""
    # Create multiple storage instances
    storage1 = await SharedTokenStorage.get_instance("http://server1", "session1")
    storage2 = await SharedTokenStorage.get_instance("http://server2", "session2")

    await storage1.set_tokens({"access_token": "token1"})
    await storage2.set_tokens({"access_token": "token2"})

    # Clear all should work without race conditions
    await SharedTokenStorage.clear_all_async()

    # Create new instances - should be empty
    storage1_new = await SharedTokenStorage.get_instance("http://server1", "session1")
    tokens = await storage1_new.get_tokens()
    assert tokens is None
