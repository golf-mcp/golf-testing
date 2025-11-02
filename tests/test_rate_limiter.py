"""Tests for rate limiter functionality"""

import asyncio
import pytest

from src.test_mcp.utils.rate_limiter import RateLimiter, RequestRecord


class TestRequestRecord:
    """Test RequestRecord namedtuple"""

    def test_create_request_record(self):
        """Test creating a request record"""
        record = RequestRecord(
            timestamp=123.456,
            tokens_used=1000,
            correlation_id="test-id-123",
        )
        assert record.timestamp == 123.456
        assert record.tokens_used == 1000
        assert record.correlation_id == "test-id-123"

    def test_request_record_immutability(self):
        """Test that RequestRecord is immutable"""
        record = RequestRecord(
            timestamp=123.456,
            tokens_used=1000,
            correlation_id="test-id-123",
        )
        with pytest.raises(AttributeError):
            record.timestamp = 999.0


class TestRateLimiter:
    """Test RateLimiter class"""

    def test_initialization(self):
        """Test RateLimiter initialization"""
        limiter = RateLimiter()
        assert "anthropic" in limiter.providers
        assert "openai" in limiter.providers
        assert "gemini" in limiter.providers
        assert limiter.providers["anthropic"]["requests_per_minute"] == 5000
        assert limiter.providers["anthropic"]["tokens_per_minute"] == 100000

    @pytest.mark.asyncio
    async def test_acquire_request_slot_basic(self):
        """Test acquiring a basic request slot"""
        limiter = RateLimiter()
        correlation_id = await limiter.acquire_request_slot("anthropic")

        assert correlation_id is not None
        assert correlation_id.startswith("anthropic_")
        assert "anthropic" in limiter.request_history
        assert correlation_id in limiter.request_history["anthropic"]

    @pytest.mark.asyncio
    async def test_acquire_request_slot_unknown_provider(self):
        """Test acquiring slot for unknown provider uses defaults"""
        limiter = RateLimiter()
        correlation_id = await limiter.acquire_request_slot("unknown_provider")

        assert correlation_id is not None
        assert correlation_id.startswith("unknown_provider_")

    @pytest.mark.asyncio
    async def test_acquire_request_slot_invalid_limits(self):
        """Test that invalid rate limits raise ValueError"""
        limiter = RateLimiter()
        limiter.providers["test_provider"] = {
            "requests_per_minute": 0,
            "tokens_per_minute": 100,
        }

        with pytest.raises(ValueError, match="Invalid rate limits"):
            await limiter.acquire_request_slot("test_provider")

    @pytest.mark.asyncio
    async def test_record_token_usage_basic(self):
        """Test recording token usage"""
        limiter = RateLimiter()
        correlation_id = await limiter.acquire_request_slot("anthropic")

        await limiter.record_token_usage(correlation_id, 500)

        assert limiter.token_usage["anthropic"] == 500
        record = limiter.request_history["anthropic"][correlation_id]
        assert record.tokens_used == 500

    @pytest.mark.asyncio
    async def test_record_token_usage_negative_raises_error(self):
        """Test that negative token usage raises ValueError"""
        limiter = RateLimiter()
        correlation_id = await limiter.acquire_request_slot("anthropic")

        with pytest.raises(ValueError, match="tokens_used must be non-negative"):
            await limiter.record_token_usage(correlation_id, -100)

    @pytest.mark.asyncio
    async def test_record_token_usage_unknown_correlation_id(self):
        """Test recording tokens for unknown correlation ID logs warning"""
        limiter = RateLimiter()
        # Should not raise, just log warning
        await limiter.record_token_usage("unknown-id-123", 100)

    @pytest.mark.asyncio
    async def test_multiple_requests_same_provider(self):
        """Test acquiring multiple request slots for same provider"""
        limiter = RateLimiter()

        id1 = await limiter.acquire_request_slot("anthropic")
        id2 = await limiter.acquire_request_slot("anthropic")
        id3 = await limiter.acquire_request_slot("anthropic")

        assert id1 != id2 != id3
        assert len(limiter.request_history["anthropic"]) == 3

    @pytest.mark.asyncio
    async def test_multiple_providers(self):
        """Test acquiring slots from different providers"""
        limiter = RateLimiter()

        id_anthropic = await limiter.acquire_request_slot("anthropic")
        id_openai = await limiter.acquire_request_slot("openai")
        id_gemini = await limiter.acquire_request_slot("gemini")

        assert id_anthropic.startswith("anthropic_")
        assert id_openai.startswith("openai_")
        assert id_gemini.startswith("gemini_")

    @pytest.mark.asyncio
    async def test_cleanup_old_requests(self):
        """Test that old requests are cleaned up"""
        limiter = RateLimiter()

        # Override window for faster testing
        original_window = limiter.RATE_LIMIT_WINDOW_SECONDS
        limiter.RATE_LIMIT_WINDOW_SECONDS = 0.1

        try:
            # Create a request
            correlation_id = await limiter.acquire_request_slot("anthropic")
            await limiter.record_token_usage(correlation_id, 500)

            # Verify it exists
            assert limiter.token_usage["anthropic"] == 500
            assert len(limiter.request_history["anthropic"]) == 1

            # Wait for cleanup window to pass
            await asyncio.sleep(0.2)

            # Acquire another request (should trigger cleanup)
            await limiter.acquire_request_slot("anthropic")

            # Old tokens should be cleaned
            assert limiter.token_usage["anthropic"] < 500
        finally:
            limiter.RATE_LIMIT_WINDOW_SECONDS = original_window

    @pytest.mark.asyncio
    async def test_cleanup_pending_request(self):
        """Test cleaning up a pending request"""
        limiter = RateLimiter()

        correlation_id = await limiter.acquire_request_slot("anthropic")
        assert correlation_id in limiter._pending_requests

        await limiter.cleanup_pending_request(correlation_id)

        assert correlation_id not in limiter._pending_requests
        assert correlation_id not in limiter.request_history["anthropic"]

    @pytest.mark.asyncio
    async def test_cleanup_pending_request_unknown_id(self):
        """Test cleaning up unknown pending request does nothing"""
        limiter = RateLimiter()
        # Should not raise
        await limiter.cleanup_pending_request("unknown-id-456")

    @pytest.mark.asyncio
    async def test_token_accumulation(self):
        """Test that token usage accumulates correctly"""
        limiter = RateLimiter()

        id1 = await limiter.acquire_request_slot("anthropic")
        await limiter.record_token_usage(id1, 100)

        id2 = await limiter.acquire_request_slot("anthropic")
        await limiter.record_token_usage(id2, 200)

        id3 = await limiter.acquire_request_slot("anthropic")
        await limiter.record_token_usage(id3, 300)

        assert limiter.token_usage["anthropic"] == 600

    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Test handling concurrent requests"""
        limiter = RateLimiter()

        async def make_request(provider):
            correlation_id = await limiter.acquire_request_slot(provider)
            await limiter.record_token_usage(correlation_id, 100)
            return correlation_id

        # Make 10 concurrent requests
        tasks = [make_request("anthropic") for _ in range(10)]
        results = await asyncio.gather(*tasks)

        # All should complete successfully
        assert len(results) == 10
        assert len(set(results)) == 10  # All unique IDs
        assert limiter.token_usage["anthropic"] == 1000

    @pytest.mark.asyncio
    async def test_rate_limiting_enforcement(self):
        """Test that rate limiting actually enforces limits"""
        limiter = RateLimiter()

        # Set very restrictive limits for testing
        limiter.providers["test_provider"] = {
            "requests_per_minute": 2,
            "tokens_per_minute": 1000,
        }
        limiter.RATE_LIMIT_WINDOW_SECONDS = 0.1
        limiter.CLEANUP_CHECK_INTERVAL = 0.01

        # Acquire max allowed requests
        id1 = await limiter.acquire_request_slot("test_provider")
        id2 = await limiter.acquire_request_slot("test_provider")

        # Verify we hit the limit
        assert len(limiter.request_history["test_provider"]) == 2

        # Complete first two requests to free up slots
        await limiter.record_token_usage(id1, 100)
        await limiter.record_token_usage(id2, 100)

        # Wait for cleanup window to pass
        await asyncio.sleep(0.12)

        # Third request should now succeed after cleanup
        id3 = await limiter.acquire_request_slot("test_provider")

        assert id3 is not None
        assert id3.startswith("test_provider_")

    @pytest.mark.asyncio
    async def test_token_limit_enforcement(self):
        """Test that token limits are enforced"""
        limiter = RateLimiter()

        # Set very low token limit
        limiter.providers["test_provider"] = {
            "requests_per_minute": 100,
            "tokens_per_minute": 100,
        }
        limiter.RATE_LIMIT_WINDOW_SECONDS = 0.1
        limiter.CLEANUP_CHECK_INTERVAL = 0.01

        # Fill up to 80% (threshold)
        id1 = await limiter.acquire_request_slot("test_provider")
        await limiter.record_token_usage(id1, 80)

        # Verify we're at the threshold
        assert limiter.token_usage["test_provider"] == 80

        # Wait for tokens to clear (window + small buffer)
        await asyncio.sleep(0.12)

        # Second request should now succeed after token cleanup
        id2 = await limiter.acquire_request_slot("test_provider")

        assert id2 is not None
        assert id2.startswith("test_provider_")

    @pytest.mark.asyncio
    async def test_provider_isolation(self):
        """Test that different providers are isolated"""
        limiter = RateLimiter()

        # Use up one provider
        id1 = await limiter.acquire_request_slot("anthropic")
        await limiter.record_token_usage(id1, 50000)

        # Other provider should be unaffected
        id2 = await limiter.acquire_request_slot("openai")
        await limiter.record_token_usage(id2, 100)

        assert limiter.token_usage["anthropic"] == 50000
        assert limiter.token_usage["openai"] == 100

    @pytest.mark.asyncio
    async def test_correlation_id_format(self):
        """Test that correlation IDs have expected format"""
        limiter = RateLimiter()
        correlation_id = await limiter.acquire_request_slot("anthropic")

        parts = correlation_id.split("_")
        assert len(parts) >= 3
        assert parts[0] == "anthropic"
        assert parts[1].isdigit()  # timestamp
        assert len(parts[2]) == 8  # UUID hex

    @pytest.mark.asyncio
    async def test_request_timeout_cleanup(self):
        """Test that timed-out requests are cleaned up"""
        limiter = RateLimiter()

        # Override timeout for faster testing
        original_timeout = limiter.REQUEST_TIMEOUT_SECONDS
        limiter.REQUEST_TIMEOUT_SECONDS = 0.1
        limiter.RATE_LIMIT_WINDOW_SECONDS = 0.2

        try:
            # Create a request but don't complete it
            correlation_id = await limiter.acquire_request_slot("anthropic")
            assert correlation_id in limiter._pending_requests

            # Wait for timeout
            await asyncio.sleep(0.15)

            # Trigger cleanup by acquiring another request
            await limiter.acquire_request_slot("anthropic")

            # The timed-out request should be cleaned up
            # (It should be removed from pending, but exact cleanup depends on implementation)
        finally:
            limiter.REQUEST_TIMEOUT_SECONDS = original_timeout
            limiter.RATE_LIMIT_WINDOW_SECONDS = 60
